/*
 * Copyright (C) 2019 The ORT Project Authors (see <https://github.com/oss-review-toolkit/ort/blob/main/NOTICE>)
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

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.readValue

import java.io.File

import org.apache.logging.log4j.kotlin.logger

import org.ossreviewtoolkit.analyzer.AbstractPackageManagerFactory
import org.ossreviewtoolkit.analyzer.PackageManager
import org.ossreviewtoolkit.analyzer.parseAuthorString
import org.ossreviewtoolkit.downloader.VcsHost
import org.ossreviewtoolkit.downloader.VersionControlSystem
import org.ossreviewtoolkit.model.Hash
import org.ossreviewtoolkit.model.HashAlgorithm
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.PackageReference
import org.ossreviewtoolkit.model.Project
import org.ossreviewtoolkit.model.ProjectAnalyzerResult
import org.ossreviewtoolkit.model.RemoteArtifact
import org.ossreviewtoolkit.model.Scope
import org.ossreviewtoolkit.model.VcsInfo
import org.ossreviewtoolkit.model.config.AnalyzerConfiguration
import org.ossreviewtoolkit.model.config.PackageManagerConfiguration
import org.ossreviewtoolkit.model.config.RepositoryConfiguration
import org.ossreviewtoolkit.model.jsonMapper
import org.ossreviewtoolkit.model.yamlMapper
import org.ossreviewtoolkit.utils.common.CommandLineTool
import org.ossreviewtoolkit.utils.common.Os
import org.ossreviewtoolkit.utils.common.fieldNamesOrEmpty
import org.ossreviewtoolkit.utils.common.masked
import org.ossreviewtoolkit.utils.common.stashDirectories
import org.ossreviewtoolkit.utils.common.textValueOrEmpty
import org.ossreviewtoolkit.utils.common.toUri
import org.ossreviewtoolkit.utils.ort.ORT_CONFIG_FILENAME
import org.ossreviewtoolkit.utils.ort.requestPasswordAuthentication

import org.semver4j.RangesList
import org.semver4j.RangesListFactory

/**
 * The [Conan](https://conan.io/) package manager for C / C++.
 *
 * This package manager supports the following [options][PackageManagerConfiguration.options]:
 * - *lockfileName*: The name of the lockfile, which is used for analysis if allowDynamicVersions is set to false.
 *   The lockfile should be located in the analysis root. Currently only one lockfile is supported per Conan project.
 * TODO: Add support for `python_requires`.
 */
class Conan(
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
            "-s", "compiler=gcc",
            "-s", "compiler.libcxx=libstdc++",
            "-s", "compiler.version=11.1"
        )

        private const val SCOPE_NAME_DEPENDENCIES = "requires"
        private const val SCOPE_NAME_DEV_DEPENDENCIES = "tool_requires"
    }

    class Factory : AbstractPackageManagerFactory<Conan>("Conan") {
        override val globsForDefinitionFiles = listOf("conanfile*.txt", "conanfile*.py")

        override fun create(
            analysisRoot: File,
            analyzerConfig: AnalyzerConfiguration,
            repoConfig: RepositoryConfiguration
        ) = Conan(type, analysisRoot, analyzerConfig, repoConfig)
    }

    private val conanHome = Os.userHomeDirectory.resolve(".conan")

    // This is where Conan caches downloaded packages [1]. Note that the package cache is not concurrent, and its
    // layout does not support packages from different remotes that are named (and versioned) the same.
    //
    // TODO: Consider using the experimental (and by default disabled) download cache [2] to lift these limitations.
    //
    // [1]: https://docs.conan.io/en/latest/reference/config_files/conan.conf.html#storage
    // [2]: https://docs.conan.io/en/latest/configuration/download_cache.html#download-cache
    private val conanStoragePath = conanHome.resolve("data")

    private val pkgInspectResults = mutableMapOf<String, JsonNode>()

    override fun command(workingDir: File?) = "conan"

    private fun hasLockfile(file: String) = File(file).isFile

    override fun transformVersion(output: String) =
        // Conan could report version strings like:
        // Conan version 1.18.0
        output.removePrefix("Conan version ")

    override fun getVersionRequirement(): RangesList = RangesListFactory.create(">=2.4.1")

    override fun beforeResolution(definitionFiles: List<File>) = checkVersion()

    /**
     * Primary method for resolving dependencies from [definitionFile].
     */
    override fun resolveDependencies(definitionFile: File, labels: Map<String, String>): List<ProjectAnalyzerResult> =
        try {
            resolvedDependenciesInternal(definitionFile)
        } finally {
            // Clear the inspection result cache, because we call "conan config install" for each definition file which
            // could overwrite the remotes and result in different metadata for packages with the same name and version.
            pkgInspectResults.clear()
        }

    private fun resolvedDependenciesInternal(definitionFile: File): List<ProjectAnalyzerResult> {
        val workingDir = definitionFile.parentFile

        // TODO: Support customizing the "conan_config" directory name, and also support getting the config from a URL.
        //       These options should be retrieved from package manager specific analyzer configuration in ".ort.yml".
        val conanConfig = sequenceOf(workingDir, analysisRoot).map { it.resolve("conan_config") }
            .find { it.isDirectory }

        val directoryToStash = conanConfig?.let { conanHome } ?: conanStoragePath

        stashDirectories(directoryToStash).use {
            configureRemoteAuthentication(conanConfig)

            // TODO: Support lockfiles which are located in a different directory than the definition file.
            val lockfileName = options[OPTION_LOCKFILE_NAME]
            requireLockfile(workingDir) { lockfileName?.let { hasLockfile(workingDir.resolve(it).path) } == true }

            val r = when(lockfileName) {
                null -> run(workingDir, "graph", "info", definitionFile.name, "--format", "json", *DUMMY_COMPILER_SETTINGS)
                else -> {
                    verifyLockfileBelongsToProject(workingDir, lockfileName)
                    run(workingDir, "graph", "info", definitionFile.name, "-l", lockfileName, "--format", "json")
                }
            }

            val graph =jsonMapper.readTree(r.stdout)

            val rootNodeIds = graph["graph"]["root"].fieldNamesOrEmpty().asSequence().toSet()

            val pkgInfos = graph["graph"]["nodes"]
            val dependencies = pkgInfos.filter {
                entry -> entry["id"].asText() !in rootNodeIds
            }

            val packages = parsePackages(dependencies)

            val dependenciesScope = Scope(
                name = SCOPE_NAME_DEPENDENCIES,
                dependencies =
                parseDependencies(pkgInfos, definitionFile.name, SCOPE_NAME_DEPENDENCIES)
            )
            val devDependenciesScope = Scope(
                name = SCOPE_NAME_DEV_DEPENDENCIES,
                dependencies =
                parseDependencies(pkgInfos, definitionFile.name, SCOPE_NAME_DEV_DEPENDENCIES)
            )

            val projectPackage = parseProjectPackage(pkgInfos, definitionFile)

            return listOf(
                ProjectAnalyzerResult(
                    project = Project(
                        id = projectPackage.id,
                        definitionFilePath = VersionControlSystem.getPathInfo(definitionFile).path,
                        authors = projectPackage.authors,
                        declaredLicenses = projectPackage.declaredLicenses,
                        vcs = projectPackage.vcs,
                        vcsProcessed = processProjectVcs(
                            workingDir,
                            projectPackage.vcs,
                            projectPackage.homepageUrl
                        ),
                        homepageUrl = projectPackage.homepageUrl,
                        scopeDependencies = setOf(dependenciesScope, devDependenciesScope)
                    ),
                    packages = packages.values.toSet()
                )
            )
        }
    }

    private fun verifyLockfileBelongsToProject(workingDir: File, lockfileName: String?) {
        require(workingDir.resolve(lockfileName.orEmpty()).canonicalFile.startsWith(workingDir.canonicalFile)) {
            "The provided lockfile path points to the directory outside of the analyzed project: '$lockfileName' and " +
                "potentially does not belong to the project. Please move the lockfile to the '$workingDir' and " +
                "set the path in '$ORT_CONFIG_FILENAME' accordingly."
        }
    }

    private fun configureRemoteAuthentication(conanConfig: File?) {
        // Install configuration from a local directory if available.
        conanConfig?.let {
            run("config", "install", it.absolutePath)
        }

        // List configured remotes in "remotes.txt" format.
        val remoteList = run("remote", "list", "--format", "json")
        if (remoteList.isError) {
            logger.warn { "Failed to list remotes." }
            return
        }

        val remoteListJson = jsonMapper.readTree(remoteList.stdout)

        // Iterate over configured remotes.
        remoteListJson.forEach { entry ->
            val remoteName = entry["name"].textValueOrEmpty()
            val remoteUrl = entry["url"].textValueOrEmpty()

            remoteUrl.toUri().onSuccess { uri ->
                logger.info { "Found remote '$remoteName' pointing to URL $remoteUrl." }

                // Request authentication for the extracted remote URL.
                val auth = requestPasswordAuthentication(uri)

                if (auth != null) {
                    // Configure Conan's authentication based on ORT's authentication for the remote.
                    runCatching {
                        run("remote", "login", "--password", String(auth.password).masked(), remoteName, auth.userName.masked())
                    }.onFailure {
                        logger.error { "Failed to configure user authentication for remote '$remoteName'." }
                    }
                }
            }.onFailure {
                logger.warn { "The remote '$remoteName' points to invalid URL $remoteUrl." }
            }
        }
    }

    /**
     * Return the dependency tree for [pkg] for the given [scopeName].
     */
    private fun parseDependencyTree(
        pkgInfos: JsonNode,
        pkg: JsonNode,
        scopeName: String,
    ): Set<PackageReference> =
        buildSet {
            pkg[scopeName]?.forEach { childNode ->
                val childRef = childNode.textValueOrEmpty()
                pkgInfos.find { it["reference"].textValueOrEmpty() == childRef }?.let { pkgInfo ->
                    logger.debug { "Found child '$childRef'." }

                    val id = parsePackageId(pkgInfo)
                    val dependencies = parseDependencyTree(pkgInfos, pkgInfo, SCOPE_NAME_DEPENDENCIES) +
                        parseDependencyTree(pkgInfos, pkgInfo, SCOPE_NAME_DEV_DEPENDENCIES)

                    this += PackageReference(id, dependencies = dependencies)
                }
            }
        }

    /**
     * Run through each package and parse the list of its dependencies (also transitive ones).
     */
    private fun parseDependencies(
        pkgInfos: JsonNode,
        definitionFileName: String,
        scopeName: String,
    ): Set<PackageReference> =
        parseDependencyTree(pkgInfos, findProjectNode(pkgInfos, definitionFileName), scopeName)

    /**
     * Return the map of packages and their identifiers which are contained in [nodes].
     */
    private fun parsePackages(nodes: List<JsonNode>): Map<String, Package> =
        nodes.associate { node ->
            val pkg = parsePackage(node)
            "${pkg.id.name}:${pkg.id.version}" to pkg
        }

    /**
     * Return the [Package] parsed from the given [node].
     */
    private fun parsePackage(node: JsonNode): Package {
        val homepageUrl = node["homepage"].textValueOrEmpty()

        val id = parsePackageId(node)
        val conanData = readConanData(node, id)

        return Package(
            id = id,
            authors = parseAuthors(node),
            declaredLicenses = parseDeclaredLicenses(node),
            description = node["description"].textValueOrEmpty(),
            homepageUrl = homepageUrl,
            binaryArtifact = RemoteArtifact.EMPTY, // TODO: implement me!
            sourceArtifact = parseSourceArtifact(conanData),
            vcs = processPackageVcs(VcsInfo.EMPTY, homepageUrl),
            isModified = "patches" in conanData
        )
    }

    /**
     * Find the node that represents the project defined in the definition file.
     */
    private fun findProjectNode(pkgInfos: JsonNode, definitionFileName: String): JsonNode =
        pkgInfos.first {
            // Use "in" because conanfile.py's reference string often includes other data.
            definitionFileName in it["label"].textValueOrEmpty()
        }

    /**
     * Return the set of declared licenses contained in [node].
     */
    private fun parseDeclaredLicenses(node: JsonNode): Set<String> =
        mutableSetOf<String>().also { licenses ->
            val licenseNode = node["license"]
            if (licenseNode.isTextual) {
                licenses.add(licenseNode.textValueOrEmpty())
            } else {
                licenseNode?.mapNotNullTo(licenses) { it.textValue() }
            }
        }

    /**
     * Return the [Identifier] for the package contained in [node].
     */
    private fun parsePackageId(node: JsonNode) =
        Identifier(
            type = "Conan",
            namespace = "",
            name = node["name"].textValueOrEmpty(),
            version = node["version"].textValueOrEmpty(),
        )

    /**
     * Return the [VcsInfo] contained in [node].
     */
    private fun parseVcsInfo(node: JsonNode): VcsInfo {
        val revision = node["revision"].textValueOrEmpty()
        val url = node["url"].textValueOrEmpty()
        val vcsInfo = VcsHost.parseUrl(url)
        return if (revision == "0") vcsInfo else vcsInfo.copy(revision = revision)
    }

    /**
     * Return the generic map of Conan data for the [id].
     */
    private fun readConanData(node: JsonNode, id: Identifier): Map<String, JsonNode> {
        return runCatching {
            val fileName = node["recipe_folder"].asText() + "/conandata.yml"
            val conanData = yamlMapper.readValue<Map<String, JsonNode>>(File(fileName))

            // Replace metadata for all version with metadata for this specific version for convenient access.
            conanData.mapValues { (key, value) ->
                when (key) {
                    "patches", "sources" -> value[id.version]
                    else -> value
                }
            }
        }.getOrDefault(emptyMap())
    }

    /**
     * Return the source artifact contained in [conanData], or [RemoteArtifact.EMPTY] if no source artifact is
     * available.
     */
    private fun parseSourceArtifact(conanData: Map<String, JsonNode>): RemoteArtifact {
        return runCatching {
            val artifactEntry = conanData.getValue("sources")

            val url = artifactEntry["url"].let { urlNode ->
                (urlNode.takeIf { it.isTextual } ?: urlNode.first()).textValueOrEmpty()
            }
            val hash = Hash.create(artifactEntry["sha256"].textValueOrEmpty(), HashAlgorithm.SHA256.name)

            RemoteArtifact(url, hash)
        }.getOrElse {
            RemoteArtifact.EMPTY
        }
    }

    /**
     * Return a [Package] containing project-level information.
     */
    private fun parseProjectPackage(pkgInfos: JsonNode, definitionFile: File): Package {
        val projectPackageJson = findProjectNode(pkgInfos, definitionFile.name)

        return Package(
            id = Identifier(
                type = managerName,
                namespace = "",
                name = projectPackageJson["label"].textValueOrEmpty(),
                version = projectPackageJson["version"].textValueOrEmpty()
            ),
            authors = parseAuthors(projectPackageJson),
            declaredLicenses = parseDeclaredLicenses(projectPackageJson),
            description = projectPackageJson["description"].textValueOrEmpty(),
            homepageUrl = projectPackageJson["homepage"].textValueOrEmpty(),
            binaryArtifact = RemoteArtifact.EMPTY, // TODO: implement me!
            sourceArtifact = RemoteArtifact.EMPTY, // TODO: implement me!
            vcs = parseVcsInfo(projectPackageJson)
        )
    }

    /**
     * Parse information about the package author from the given JSON [node]. If present, return a set containing the
     * author name; otherwise, return an empty set.
     */
    private fun parseAuthors(node: JsonNode): Set<String> =
        setOfNotNull(parseAuthorString(node["author"]?.textValue(), '<', '('))
}
