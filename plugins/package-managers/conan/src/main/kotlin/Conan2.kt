/*
 * Copyright (C) 2024 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

package org.ossreviewtoolkit.plugins.packagemanagers.conan

import com.charleskorn.kaml.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.*
import org.ossreviewtoolkit.analyzer.AbstractPackageManagerFactory
import org.ossreviewtoolkit.analyzer.PackageManager
import org.ossreviewtoolkit.analyzer.parseAuthorString
import org.ossreviewtoolkit.downloader.VersionControlSystem
import org.ossreviewtoolkit.model.*
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration
import org.ossreviewtoolkit.model.config.RepositoryConfiguration
import org.ossreviewtoolkit.utils.common.CommandLineTool
import org.semver4j.RangesList
import org.semver4j.RangesListFactory
import java.io.File

/**
 * The [Conan](https://conan.io/) package manager for C / C++, version 2.x.
 *
 * This package manager supports the following [options][PackageManagerConfiguration.options]:
 * - *lockfileName*: The name of the lockfile, which is used for analysis if allowDynamicVersions is set to false.
 *   The lockfile should be located in the analysis root. Currently only one lockfile is supported per Conan project.
 */
class Conan2(
    name: String,
    analysisRoot: File,
    analyzerConfig: AnalyzerConfiguration,
    repoConfig: RepositoryConfiguration
) : PackageManager(name, analysisRoot, analyzerConfig, repoConfig), CommandLineTool {
    companion object {
        /**
         * The name of the option to specify the name of the lockfile.
         */
        const val OPTION_LOCKFILE_NAME = "lockfileName"

        private val DUMMY_COMPILER_SETTINGS = arrayOf(
            "--settings:all", "compiler=gcc",
            "--settings:all", "compiler.libcxx=libstdc++",
            "--settings:all", "compiler.version=11.1"
        )

        private const val SCOPE_NAME_REQUIRES = "requires"
        private const val SCOPE_NAME_BUILD_REQUIRES = "tool_requires"
    }

    class Factory : AbstractPackageManagerFactory<Conan2>("Conan2") {
        override val globsForDefinitionFiles = listOf("conanfile*.txt", "conanfile*.py")

        override fun create(
            analysisRoot: File,
            analyzerConfig: AnalyzerConfiguration,
            repoConfig: RepositoryConfiguration
        ): Conan2 = Conan2(type, analysisRoot, analyzerConfig, repoConfig)
    }

    override fun resolveDependencies(definitionFile: File, labels: Map<String, String>): List<ProjectAnalyzerResult> {
        val workingDir = definitionFile.parentFile
        val conanGraphInfoResult = when (val lockfileName = options[Conan2.OPTION_LOCKFILE_NAME]) {
            null -> run(workingDir, "graph", "info", definitionFile.name, "--format", "json", *DUMMY_COMPILER_SETTINGS)
            else -> run(
                workingDir,
                "graph",
                "info",
                definitionFile.name,
                "--lockfile",
                lockfileName,
                "--format",
                "json"
            )
        }

        val conanGraph = parseGraph(conanGraphInfoResult.stdout)
        assert(conanGraph.root.keys == setOf("0"))
        val projectPackage = conanGraph.nodes.getValue("0")
        val homepageUrl = projectPackage.homepage.orEmpty()
        val packages = parsePackages(projectPackage, conanGraph.nodes.values)

        val requiresDependenciesScope = Scope(
            name = SCOPE_NAME_REQUIRES,
            dependencies = parseDependencyTreeRequires(packages, conanGraph.nodes, projectPackage)
        )

        val toolRequiresDependenciesScope = Scope(
            name = SCOPE_NAME_BUILD_REQUIRES,
            dependencies = parseDependencyTreeBuildRequires(packages, conanGraph.nodes, projectPackage)
        )

        return listOf(
            ProjectAnalyzerResult(
                project = Project(
                    id = Identifier(
                        type = managerName,
                        namespace = "",
                        name = definitionFile.name,
                        version = projectPackage.version.orEmpty()
                    ),
                    definitionFilePath = VersionControlSystem.getPathInfo(definitionFile).path,
                    authors = setOfNotNull(projectPackage.author),
                    declaredLicenses = projectPackage.license.toSet(),
                    vcs = processPackageVcs(VcsInfo.EMPTY, homepageUrl),
                    homepageUrl = homepageUrl,
                    scopeDependencies = setOf(requiresDependenciesScope, toolRequiresDependenciesScope)
                ),
                packages = packages.values.toSet()
            )
        )
    }

    private fun parseDependencyTreeBuildRequires(
        packages: Map<String, Package>,
        graphNodes: Map<String, GraphNode>,
        dependant: GraphNode,
    ): Set<PackageReference> =
        buildSet {
            dependant.dependencies.forEach { (id, details) ->
                val node = graphNodes.getValue(id)
                if (details.build) {
                    // Dependency and all it transitive dependencies are build dependencies
                    this += PackageReference(
                        id = packages.getValue("${node.name}:${node.version}").id,
                        dependencies = parseDependencyTreeRequires(packages, graphNodes, node, false),
                    )
                } else {
                    /* This dependency is not a build time dependency, but its transitive dependencies might be */
                    this += parseDependencyTreeBuildRequires(packages, graphNodes, node)
                }
            }
        }

    private fun parseDependencyTreeRequires(
        packages: Map<String, Package>,
        graphNodes: Map<String, GraphNode>,
        dependant: GraphNode,
        ignoreBuildDeps: Boolean = true,
    ): Set<PackageReference> =
        buildSet {
            dependant.dependencies.forEach { (id, details) ->
                if (ignoreBuildDeps && details.build)
                    return@forEach
                val node = graphNodes.getValue(id)
                this += PackageReference(
                    id = packages.getValue("${node.name}:${node.version}").id,
                    dependencies = parseDependencyTreeRequires(packages, graphNodes, node),
                )
            }
        }

    /** Return the map of packages and their identifiers (name:version) */
    private fun parsePackages(
        rootPackageGraphNode: GraphNode,
        allPackageGraphNodes: Collection<GraphNode>
    ): Map<String, Package> =
        buildMap {
            allPackageGraphNodes.forEach {
                // Skip root node
                if (it == rootPackageGraphNode) return@forEach
                val homepageUrl = it.homepage.orEmpty()

                val conanData = readConanData(it)
                val id = graphNodeToIdentifier(it)

                this += "${id.name}:${id.version}" to Package(
                    id = id,
                    authors = setOfNotNull(parseAuthorString(it.author.orEmpty(), '<', '(')),
                    declaredLicenses = it.license,
                    description = it.description.orEmpty(),
                    homepageUrl = homepageUrl,
                    binaryArtifact = RemoteArtifact.EMPTY,
                    sourceArtifact = parseSourceArtifact(conanData),
                    vcs = processPackageVcs(VcsInfo.EMPTY, homepageUrl),
                    isModified = conanData.hasPatches,
                )
            }
        }

    // Return the source artifact contained in [conanData], or [RemoteArtifact.EMPTY] if no source artifact is
    // available.
    private fun parseSourceArtifact(conanData: Conan2Data): RemoteArtifact {
        val url = conanData.url ?: return RemoteArtifact.EMPTY
        val hashValue = conanData.sha256.orEmpty()
        val hash = Hash.NONE.takeIf { hashValue.isEmpty() } ?: Hash(hashValue, HashAlgorithm.SHA256)

        return RemoteArtifact(url, hash)
    }

    override fun command(workingDir: File?) = "conan"

    // Conan could report version strings like:
    // Conan version 2.5.0
    override fun transformVersion(output: String) = output.removePrefix("Conan version ")

    override fun getVersionRequirement(): RangesList = RangesListFactory.create(">=2.5")
}

private data class Conan2Data(
    val url: String?,
    val sha256: String?,
    val hasPatches: Boolean
)

private fun readConanData(graphNode: GraphNode): Conan2Data {
    val conanDataFile = File(graphNode.recipeFolder.orEmpty() + "/conandata.yml")
    val root = Yaml.default.parseToYamlNode(conanDataFile.readText()).yamlMap
    val version = graphNode.version.orEmpty()

    val patchesForVersion = root.get<YamlMap>("patches")?.get<YamlList>(version)
    val hasPatches = !patchesForVersion?.items.isNullOrEmpty()

    val sourceForVersion = root.get<YamlMap>("sources")?.get<YamlMap>(version)
    val sha256 = sourceForVersion?.get<YamlScalar>("sha256")?.content

    val url = sourceForVersion?.get<YamlNode>("url")?.let {
        when {
            it is YamlList -> it.yamlList.items.firstOrNull()?.yamlScalar?.content
            else -> it.yamlScalar.content
        }
    }

    return Conan2Data(url, sha256, hasPatches)
}

private val JSON = Json {
    ignoreUnknownKeys = true
    allowTrailingComma = true
    namingStrategy = JsonNamingStrategy.SnakeCase
}

internal fun parseGraph(s: String): Graph {
    val topLevel: Map<String, Graph> = JSON.decodeFromString(s)
    assert(topLevel.keys == setOf("graph"))
    return topLevel.getValue("graph")
}

@Serializable
internal data class GraphDependency(
    val ref: String,
    val direct: Boolean,
    val build: Boolean,
)

@Serializable
internal data class GraphNode(
    val ref: String,
    val id: String,
    @Serializable(with = LicenseListSerializer::class)
    val license: Set<String> = emptySet(),
    val description: String? = null,
    val author: String? = null,
    val homepage: String? = null,
    val version: String? = null,
    val url: String? = null,
    val name: String? = null,
    val label: String,
    val recipeFolder: String? = null,
    val dependencies: Map<String, GraphDependency> = emptyMap(),
)

internal fun graphNodeToIdentifier(graphNode: GraphNode) =
    Identifier(
        type = "Conan",
        namespace = "",
        name = graphNode.name.orEmpty(),
        version = graphNode.version.orEmpty()
    )

object LicenseListSerializer : JsonTransformingSerializer<Set<String>>(SetSerializer(String.serializer())) {
    override fun transformDeserialize(element: JsonElement): JsonElement {
        if (element is JsonNull) {
            return JsonArray(listOf())
        }

        return if (element !is JsonArray) JsonArray(listOf(element)) else element
    }
}

@Serializable
internal data class Graph(
    val nodes: Map<String, GraphNode> = emptyMap(),
    val root: Map<String, String> = emptyMap(),
)
