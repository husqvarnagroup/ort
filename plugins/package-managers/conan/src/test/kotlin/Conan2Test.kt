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

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe

class Conan2Test : StringSpec({
    "parsePackages() parse single node" {
        val jsonString = """
            {
                "graph": {
                    "nodes": {
                        "0": {
                            "ref": "libcurl/7.85.0#d671ff2c55730f4b068bb66853c35bfc",
                            "id": "1",
                            "name": "libcurl",
                            "label": "libcurl/7.85.0",
                            "recipe_folder": "/home/user/.conan2/p/libcu4a86ede08c3bd/e",
                            "dependencies": {
                                "2": {
                                    "ref": "openssl/3.2.2",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": true,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                },
                            },
                        }
                    },
                },
            }
            """.trimIndent()

        val conanGraph = parseGraph(jsonString)

        conanGraph.nodes.keys shouldBe setOf("0")
        val nodeInfo = conanGraph.nodes.getValue("0")
        nodeInfo.ref shouldBe "libcurl/7.85.0#d671ff2c55730f4b068bb66853c35bfc"
        nodeInfo.id shouldBe "1"
        nodeInfo.name shouldBe "libcurl"
        nodeInfo.label shouldBe "libcurl/7.85.0"
        nodeInfo.recipeFolder shouldBe "/home/user/.conan2/p/libcu4a86ede08c3bd/e"
        nodeInfo.dependencies.keys shouldBe setOf("2")
        val dependencyNode = nodeInfo.dependencies.getValue("2")
        dependencyNode.ref shouldBe "openssl/3.2.2"
        dependencyNode.direct shouldBe true
        dependencyNode.build shouldBe false
    }

    "parsePackages() parse full graph" {
        val jsonString = """
            {
                "graph": {
                    "nodes": {
                        "0": {
                            "ref": "conanfile",
                            "id": "0",
                            "recipe": "Consumer",
                            "package_id": null,
                            "prev": null,
                            "rrev": null,
                            "rrev_timestamp": null,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": null,
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": null,
                            "user": null,
                            "channel": null,
                            "url": null,
                            "license": null,
                            "author": null,
                            "description": null,
                            "homepage": null,
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": null,
                            "topics": null,
                            "package_type": "unknown",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [
                                "cmake"
                            ],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": null,
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "conanfile.txt",
                            "vendor": false,
                            "dependencies": {
                                "1": {
                                    "ref": "libcurl/7.85.0",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": true,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "2": {
                                    "ref": "openssl/3.2.2",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "3": {
                                    "ref": "zlib/1.2.13",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": true,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "23": {
                                    "ref": "libxslt/1.1.34",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "host",
                            "test": false
                        },
                        "1": {
                            "ref": "libcurl/7.85.0#d671ff2c55730f4b068bb66853c35bfc",
                            "id": "1",
                            "recipe": "Cache",
                            "package_id": "ecf1a71232cb830d37815e87cfe8c83c3c5980e7",
                            "prev": null,
                            "rrev": "d671ff2c55730f4b068bb66853c35bfc",
                            "rrev_timestamp": 1717082897.939,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": "Missing",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "libcurl",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "curl",
                            "author": null,
                            "description": "command line tool and library for transferring data with URLs",
                            "homepage": "https://curl.se",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true,
                                "with_ssl": "openssl",
                                "with_dict": true,
                                "with_file": true,
                                "with_ftp": true,
                                "with_gopher": true,
                                "with_http": true,
                                "with_imap": true,
                                "with_ldap": false,
                                "with_mqtt": true,
                                "with_pop3": true,
                                "with_rtsp": true,
                                "with_smb": true,
                                "with_smtp": true,
                                "with_telnet": true,
                                "with_tftp": true,
                                "with_libssh2": false,
                                "with_libidn": false,
                                "with_librtmp": false,
                                "with_libgsasl": false,
                                "with_libpsl": false,
                                "with_largemaxwritesize": false,
                                "with_nghttp2": false,
                                "with_zlib": true,
                                "with_brotli": false,
                                "with_zstd": false,
                                "with_c_ares": false,
                                "with_threaded_resolver": true,
                                "with_proxy": true,
                                "with_crypto_auth": true,
                                "with_ntlm": true,
                                "with_ntlm_wb": true,
                                "with_cookies": true,
                                "with_ipv6": true,
                                "with_docs": false,
                                "with_misc_docs": false,
                                "with_verbose_debug": true,
                                "with_symbol_hiding": false,
                                "with_unix_sockets": true,
                                "with_verbose_strings": true,
                                "with_ca_bundle": "auto",
                                "with_ca_path": "auto",
                                "with_ca_fallback": false
                            },
                            "options_description": null,
                            "version": "7.85.0",
                            "topics": [
                                "curl",
                                "data-transfer",
                                "ftp",
                                "gopher",
                                "http",
                                "imap",
                                "ldap",
                                "mqtt",
                                "pop3",
                                "rtmp",
                                "rtsp",
                                "scp",
                                "sftp",
                                "smb",
                                "smtp",
                                "telnet",
                                "tftp"
                            ],
                            "package_type": "static-library",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "fPIC": "True",
                                "shared": "False",
                                "with_brotli": "False",
                                "with_c_ares": "False",
                                "with_ca_bundle": "auto",
                                "with_ca_fallback": "False",
                                "with_ca_path": "auto",
                                "with_cookies": "True",
                                "with_crypto_auth": "True",
                                "with_dict": "True",
                                "with_docs": "False",
                                "with_file": "True",
                                "with_ftp": "True",
                                "with_gopher": "True",
                                "with_http": "True",
                                "with_imap": "True",
                                "with_ipv6": "True",
                                "with_largemaxwritesize": "False",
                                "with_ldap": "False",
                                "with_libgsasl": "False",
                                "with_libidn": "False",
                                "with_libpsl": "False",
                                "with_librtmp": "False",
                                "with_libssh2": "False",
                                "with_mqtt": "True",
                                "with_nghttp2": "False",
                                "with_ntlm": "True",
                                "with_ntlm_wb": "True",
                                "with_pop3": "True",
                                "with_proxy": "True",
                                "with_rtsp": "True",
                                "with_smb": "True",
                                "with_smtp": "True",
                                "with_ssl": "openssl",
                                "with_symbol_hiding": "False",
                                "with_telnet": "True",
                                "with_tftp": "True",
                                "with_threaded_resolver": "True",
                                "with_unix_sockets": "True",
                                "with_verbose_debug": "True",
                                "with_verbose_strings": "True",
                                "with_zlib": "True",
                                "with_zstd": "False"
                            },
                            "options_definitions": {
                                "shared": [
                                    "True",
                                    "False"
                                ],
                                "fPIC": [
                                    "True",
                                    "False"
                                ],
                                "with_ssl": [
                                    "False",
                                    "openssl",
                                    "wolfssl",
                                    "schannel",
                                    "darwinssl",
                                    "mbedtls"
                                ],
                                "with_file": [
                                    "True",
                                    "False"
                                ],
                                "with_ftp": [
                                    "True",
                                    "False"
                                ],
                                "with_http": [
                                    "True",
                                    "False"
                                ],
                                "with_ldap": [
                                    "True",
                                    "False"
                                ],
                                "with_rtsp": [
                                    "True",
                                    "False"
                                ],
                                "with_dict": [
                                    "True",
                                    "False"
                                ],
                                "with_telnet": [
                                    "True",
                                    "False"
                                ],
                                "with_tftp": [
                                    "True",
                                    "False"
                                ],
                                "with_pop3": [
                                    "True",
                                    "False"
                                ],
                                "with_imap": [
                                    "True",
                                    "False"
                                ],
                                "with_smb": [
                                    "True",
                                    "False"
                                ],
                                "with_smtp": [
                                    "True",
                                    "False"
                                ],
                                "with_gopher": [
                                    "True",
                                    "False"
                                ],
                                "with_mqtt": [
                                    "True",
                                    "False"
                                ],
                                "with_libssh2": [
                                    "True",
                                    "False"
                                ],
                                "with_libidn": [
                                    "True",
                                    "False"
                                ],
                                "with_librtmp": [
                                    "True",
                                    "False"
                                ],
                                "with_libgsasl": [
                                    "True",
                                    "False"
                                ],
                                "with_libpsl": [
                                    "True",
                                    "False"
                                ],
                                "with_largemaxwritesize": [
                                    "True",
                                    "False"
                                ],
                                "with_nghttp2": [
                                    "True",
                                    "False"
                                ],
                                "with_zlib": [
                                    "True",
                                    "False"
                                ],
                                "with_brotli": [
                                    "True",
                                    "False"
                                ],
                                "with_zstd": [
                                    "True",
                                    "False"
                                ],
                                "with_c_ares": [
                                    "True",
                                    "False"
                                ],
                                "with_threaded_resolver": [
                                    "True",
                                    "False"
                                ],
                                "with_proxy": [
                                    "True",
                                    "False"
                                ],
                                "with_crypto_auth": [
                                    "True",
                                    "False"
                                ],
                                "with_ntlm": [
                                    "True",
                                    "False"
                                ],
                                "with_ntlm_wb": [
                                    "True",
                                    "False"
                                ],
                                "with_cookies": [
                                    "True",
                                    "False"
                                ],
                                "with_ipv6": [
                                    "True",
                                    "False"
                                ],
                                "with_docs": [
                                    "True",
                                    "False"
                                ],
                                "with_verbose_debug": [
                                    "True",
                                    "False"
                                ],
                                "with_symbol_hiding": [
                                    "True",
                                    "False"
                                ],
                                "with_unix_sockets": [
                                    "True",
                                    "False"
                                ],
                                "with_verbose_strings": [
                                    "True",
                                    "False"
                                ],
                                "with_ca_bundle": [
                                    "False",
                                    "auto",
                                    "ANY"
                                ],
                                "with_ca_path": [
                                    "False",
                                    "auto",
                                    "ANY"
                                ],
                                "with_ca_fallback": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/libcu4a86ede08c3bd/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "libcurl/7.85.0",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "compiler": "gcc",
                                    "compiler.version": "12",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "fPIC": "True",
                                    "shared": "False",
                                    "with_brotli": "False",
                                    "with_c_ares": "False",
                                    "with_ca_bundle": "auto",
                                    "with_ca_fallback": "False",
                                    "with_ca_path": "auto",
                                    "with_cookies": "True",
                                    "with_crypto_auth": "True",
                                    "with_dict": "True",
                                    "with_docs": "False",
                                    "with_file": "True",
                                    "with_ftp": "True",
                                    "with_gopher": "True",
                                    "with_http": "True",
                                    "with_imap": "True",
                                    "with_ipv6": "True",
                                    "with_largemaxwritesize": "False",
                                    "with_ldap": "False",
                                    "with_libgsasl": "False",
                                    "with_libidn": "False",
                                    "with_libpsl": "False",
                                    "with_librtmp": "False",
                                    "with_libssh2": "False",
                                    "with_mqtt": "True",
                                    "with_nghttp2": "False",
                                    "with_ntlm": "True",
                                    "with_ntlm_wb": "True",
                                    "with_pop3": "True",
                                    "with_proxy": "True",
                                    "with_rtsp": "True",
                                    "with_smb": "True",
                                    "with_smtp": "True",
                                    "with_ssl": "openssl",
                                    "with_symbol_hiding": "False",
                                    "with_telnet": "True",
                                    "with_tftp": "True",
                                    "with_threaded_resolver": "True",
                                    "with_unix_sockets": "True",
                                    "with_verbose_debug": "True",
                                    "with_verbose_strings": "True",
                                    "with_zlib": "True",
                                    "with_zstd": "False"
                                },
                                "requires": [
                                    "openssl/3.2.Z",
                                    "zlib/1.2.Z"
                                ]
                            },
                            "vendor": false,
                            "dependencies": {
                                "2": {
                                    "ref": "openssl/3.2.2",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": true,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                },
                                "3": {
                                    "ref": "zlib/1.2.13",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": true,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                },
                                "4": {
                                    "ref": "libtool/2.4.7",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "5": {
                                    "ref": "automake/1.16.5",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "6": {
                                    "ref": "autoconf/2.71",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "7": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "20": {
                                    "ref": "pkgconf/2.1.0",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "host",
                            "test": false
                        },
                        "2": {
                            "ref": "openssl/3.2.2#899583c694f9deccec74dbe0bbc65a15",
                            "id": "2",
                            "recipe": "Cache",
                            "package_id": "558f02f9e5913e40345649000fc394cf372f32c7",
                            "prev": null,
                            "rrev": "899583c694f9deccec74dbe0bbc65a15",
                            "rrev_timestamp": 1717540517.968,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": "Missing",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "openssl",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "Apache-2.0",
                            "author": null,
                            "description": "A toolkit for the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols",
                            "homepage": "https://github.com/openssl/openssl",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true,
                                "enable_weak_ssl_ciphers": false,
                                "386": false,
                                "capieng_dialog": false,
                                "enable_capieng": false,
                                "enable_trace": false,
                                "no_aria": false,
                                "no_apps": false,
                                "no_autoload_config": false,
                                "no_asm": false,
                                "no_async": false,
                                "no_blake2": false,
                                "no_bf": false,
                                "no_camellia": false,
                                "no_chacha": false,
                                "no_cms": false,
                                "no_comp": false,
                                "no_ct": false,
                                "no_cast": false,
                                "no_deprecated": false,
                                "no_des": false,
                                "no_dgram": false,
                                "no_dh": false,
                                "no_dsa": false,
                                "no_dso": false,
                                "no_ec": false,
                                "no_ecdh": false,
                                "no_ecdsa": false,
                                "no_engine": false,
                                "no_filenames": false,
                                "no_fips": false,
                                "no_gost": false,
                                "no_idea": false,
                                "no_legacy": false,
                                "no_md2": true,
                                "no_md4": false,
                                "no_mdc2": false,
                                "no_module": false,
                                "no_ocsp": false,
                                "no_pinshared": false,
                                "no_rc2": false,
                                "no_rc4": false,
                                "no_rc5": false,
                                "no_rfc3779": false,
                                "no_rmd160": false,
                                "no_sm2": false,
                                "no_sm3": false,
                                "no_sm4": false,
                                "no_srp": false,
                                "no_srtp": false,
                                "no_sse2": false,
                                "no_ssl": false,
                                "no_stdio": false,
                                "no_seed": false,
                                "no_sock": false,
                                "no_ssl3": false,
                                "no_threads": false,
                                "no_tls1": false,
                                "no_ts": false,
                                "no_whirlpool": false,
                                "no_zlib": false,
                                "openssldir": null,
                                "tls_security_level": null
                            },
                            "options_description": null,
                            "version": "3.2.2",
                            "topics": [
                                "ssl",
                                "tls",
                                "encryption",
                                "security"
                            ],
                            "package_type": "static-library",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "386": "False",
                                "enable_trace": "False",
                                "enable_weak_ssl_ciphers": "False",
                                "fPIC": "True",
                                "no_apps": "False",
                                "no_aria": "False",
                                "no_asm": "False",
                                "no_async": "False",
                                "no_autoload_config": "False",
                                "no_bf": "False",
                                "no_blake2": "False",
                                "no_camellia": "False",
                                "no_cast": "False",
                                "no_chacha": "False",
                                "no_cms": "False",
                                "no_comp": "False",
                                "no_ct": "False",
                                "no_deprecated": "False",
                                "no_des": "False",
                                "no_dgram": "False",
                                "no_dh": "False",
                                "no_dsa": "False",
                                "no_dso": "False",
                                "no_ec": "False",
                                "no_ecdh": "False",
                                "no_ecdsa": "False",
                                "no_engine": "False",
                                "no_filenames": "False",
                                "no_fips": "False",
                                "no_gost": "False",
                                "no_idea": "False",
                                "no_legacy": "False",
                                "no_md2": "True",
                                "no_md4": "False",
                                "no_mdc2": "False",
                                "no_module": "False",
                                "no_ocsp": "False",
                                "no_pinshared": "False",
                                "no_rc2": "False",
                                "no_rc4": "False",
                                "no_rc5": "False",
                                "no_rfc3779": "False",
                                "no_rmd160": "False",
                                "no_seed": "False",
                                "no_sm2": "False",
                                "no_sm3": "False",
                                "no_sm4": "False",
                                "no_sock": "False",
                                "no_srp": "False",
                                "no_srtp": "False",
                                "no_sse2": "False",
                                "no_ssl": "False",
                                "no_ssl3": "False",
                                "no_stdio": "False",
                                "no_threads": "False",
                                "no_tls1": "False",
                                "no_ts": "False",
                                "no_whirlpool": "False",
                                "no_zlib": "False",
                                "openssldir": null,
                                "shared": "False",
                                "tls_security_level": null
                            },
                            "options_definitions": {
                                "shared": [
                                    "True",
                                    "False"
                                ],
                                "fPIC": [
                                    "True",
                                    "False"
                                ],
                                "enable_weak_ssl_ciphers": [
                                    "True",
                                    "False"
                                ],
                                "386": [
                                    "True",
                                    "False"
                                ],
                                "enable_trace": [
                                    "True",
                                    "False"
                                ],
                                "no_aria": [
                                    "True",
                                    "False"
                                ],
                                "no_apps": [
                                    "True",
                                    "False"
                                ],
                                "no_autoload_config": [
                                    "True",
                                    "False"
                                ],
                                "no_asm": [
                                    "True",
                                    "False"
                                ],
                                "no_async": [
                                    "True",
                                    "False"
                                ],
                                "no_blake2": [
                                    "True",
                                    "False"
                                ],
                                "no_bf": [
                                    "True",
                                    "False"
                                ],
                                "no_camellia": [
                                    "True",
                                    "False"
                                ],
                                "no_chacha": [
                                    "True",
                                    "False"
                                ],
                                "no_cms": [
                                    "True",
                                    "False"
                                ],
                                "no_comp": [
                                    "True",
                                    "False"
                                ],
                                "no_ct": [
                                    "True",
                                    "False"
                                ],
                                "no_cast": [
                                    "True",
                                    "False"
                                ],
                                "no_deprecated": [
                                    "True",
                                    "False"
                                ],
                                "no_des": [
                                    "True",
                                    "False"
                                ],
                                "no_dgram": [
                                    "True",
                                    "False"
                                ],
                                "no_dh": [
                                    "True",
                                    "False"
                                ],
                                "no_dsa": [
                                    "True",
                                    "False"
                                ],
                                "no_dso": [
                                    "True",
                                    "False"
                                ],
                                "no_ec": [
                                    "True",
                                    "False"
                                ],
                                "no_ecdh": [
                                    "True",
                                    "False"
                                ],
                                "no_ecdsa": [
                                    "True",
                                    "False"
                                ],
                                "no_engine": [
                                    "True",
                                    "False"
                                ],
                                "no_filenames": [
                                    "True",
                                    "False"
                                ],
                                "no_fips": [
                                    "True",
                                    "False"
                                ],
                                "no_gost": [
                                    "True",
                                    "False"
                                ],
                                "no_idea": [
                                    "True",
                                    "False"
                                ],
                                "no_legacy": [
                                    "True",
                                    "False"
                                ],
                                "no_md2": [
                                    "True",
                                    "False"
                                ],
                                "no_md4": [
                                    "True",
                                    "False"
                                ],
                                "no_mdc2": [
                                    "True",
                                    "False"
                                ],
                                "no_module": [
                                    "True",
                                    "False"
                                ],
                                "no_ocsp": [
                                    "True",
                                    "False"
                                ],
                                "no_pinshared": [
                                    "True",
                                    "False"
                                ],
                                "no_rc2": [
                                    "True",
                                    "False"
                                ],
                                "no_rc4": [
                                    "True",
                                    "False"
                                ],
                                "no_rc5": [
                                    "True",
                                    "False"
                                ],
                                "no_rfc3779": [
                                    "True",
                                    "False"
                                ],
                                "no_rmd160": [
                                    "True",
                                    "False"
                                ],
                                "no_sm2": [
                                    "True",
                                    "False"
                                ],
                                "no_sm3": [
                                    "True",
                                    "False"
                                ],
                                "no_sm4": [
                                    "True",
                                    "False"
                                ],
                                "no_srp": [
                                    "True",
                                    "False"
                                ],
                                "no_srtp": [
                                    "True",
                                    "False"
                                ],
                                "no_sse2": [
                                    "True",
                                    "False"
                                ],
                                "no_ssl": [
                                    "True",
                                    "False"
                                ],
                                "no_stdio": [
                                    "True",
                                    "False"
                                ],
                                "no_seed": [
                                    "True",
                                    "False"
                                ],
                                "no_sock": [
                                    "True",
                                    "False"
                                ],
                                "no_ssl3": [
                                    "True",
                                    "False"
                                ],
                                "no_threads": [
                                    "True",
                                    "False"
                                ],
                                "no_tls1": [
                                    "True",
                                    "False"
                                ],
                                "no_ts": [
                                    "True",
                                    "False"
                                ],
                                "no_whirlpool": [
                                    "True",
                                    "False"
                                ],
                                "no_zlib": [
                                    "True",
                                    "False"
                                ],
                                "openssldir": [
                                    null,
                                    "ANY"
                                ],
                                "tls_security_level": [
                                    null,
                                    "0",
                                    "1",
                                    "2",
                                    "3",
                                    "4",
                                    "5"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/opens464b5c427ce9d/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "openssl/3.2.2",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "compiler": "gcc",
                                    "compiler.version": "12",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "386": "False",
                                    "enable_trace": "False",
                                    "enable_weak_ssl_ciphers": "False",
                                    "fPIC": "True",
                                    "no_apps": "False",
                                    "no_aria": "False",
                                    "no_asm": "False",
                                    "no_async": "False",
                                    "no_autoload_config": "False",
                                    "no_bf": "False",
                                    "no_blake2": "False",
                                    "no_camellia": "False",
                                    "no_cast": "False",
                                    "no_chacha": "False",
                                    "no_cms": "False",
                                    "no_comp": "False",
                                    "no_ct": "False",
                                    "no_deprecated": "False",
                                    "no_des": "False",
                                    "no_dgram": "False",
                                    "no_dh": "False",
                                    "no_dsa": "False",
                                    "no_dso": "False",
                                    "no_ec": "False",
                                    "no_ecdh": "False",
                                    "no_ecdsa": "False",
                                    "no_engine": "False",
                                    "no_filenames": "False",
                                    "no_fips": "False",
                                    "no_gost": "False",
                                    "no_idea": "False",
                                    "no_legacy": "False",
                                    "no_md2": "True",
                                    "no_md4": "False",
                                    "no_mdc2": "False",
                                    "no_module": "False",
                                    "no_ocsp": "False",
                                    "no_pinshared": "False",
                                    "no_rc2": "False",
                                    "no_rc4": "False",
                                    "no_rc5": "False",
                                    "no_rfc3779": "False",
                                    "no_rmd160": "False",
                                    "no_seed": "False",
                                    "no_sm2": "False",
                                    "no_sm3": "False",
                                    "no_sm4": "False",
                                    "no_sock": "False",
                                    "no_srp": "False",
                                    "no_srtp": "False",
                                    "no_sse2": "False",
                                    "no_ssl": "False",
                                    "no_ssl3": "False",
                                    "no_stdio": "False",
                                    "no_threads": "False",
                                    "no_tls1": "False",
                                    "no_ts": "False",
                                    "no_whirlpool": "False",
                                    "no_zlib": "False",
                                    "openssldir": null,
                                    "shared": "False",
                                    "tls_security_level": null
                                },
                                "requires": [
                                    "zlib/1.2.Z"
                                ]
                            },
                            "vendor": false,
                            "dependencies": {
                                "3": {
                                    "ref": "zlib/1.2.13",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": true,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                }
                            },
                            "context": "host",
                            "test": false
                        },
                        "3": {
                            "ref": "zlib/1.2.13#4e74ebf1361fe6fb60326f473f276eb5",
                            "id": "3",
                            "recipe": "Cache",
                            "package_id": "5bc851010eb7b707e5cb2e24cb8ccf0f27989fa9",
                            "prev": null,
                            "rrev": "4e74ebf1361fe6fb60326f473f276eb5",
                            "rrev_timestamp": 1705999194.457,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": "Missing",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "zlib",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "Zlib",
                            "author": null,
                            "description": "A Massively Spiffy Yet Delicately Unobtrusive Compression Library (Also Free, Not to Mention Unencumbered by Patents)",
                            "homepage": "https://zlib.net",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true
                            },
                            "options_description": null,
                            "version": "1.2.13",
                            "topics": [
                                "zlib",
                                "compression"
                            ],
                            "package_type": "static-library",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "fPIC": "True",
                                "shared": "False"
                            },
                            "options_definitions": {
                                "shared": [
                                    "True",
                                    "False"
                                ],
                                "fPIC": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/zlibb185441d485f6/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "zlib/1.2.13",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "compiler": "gcc",
                                    "compiler.version": "12",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "fPIC": "True",
                                    "shared": "False"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "host",
                            "test": false
                        },
                        "4": {
                            "ref": "libtool/2.4.7#08316dad5c72c541ed21e039e4cf217b",
                            "id": "4",
                            "recipe": "Cache",
                            "package_id": "5bc851010eb7b707e5cb2e24cb8ccf0f27989fa9",
                            "prev": null,
                            "rrev": "08316dad5c72c541ed21e039e4cf217b",
                            "rrev_timestamp": 1702300906.107,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "libtool",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": [
                                "GPL-2.0-or-later",
                                "GPL-3.0-or-later"
                            ],
                            "author": null,
                            "description": "GNU libtool is a generic library support script. ",
                            "homepage": "https://www.gnu.org/software/libtool/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true
                            },
                            "options_description": null,
                            "version": "2.4.7",
                            "topics": [
                                "configure",
                                "library",
                                "shared",
                                "static"
                            ],
                            "package_type": "static-library",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "fPIC": "True",
                                "shared": "False"
                            },
                            "options_definitions": {
                                "shared": [
                                    "True",
                                    "False"
                                ],
                                "fPIC": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/libto0f3efefe94abb/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "libtool/2.4.7",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "compiler": "gcc",
                                    "compiler.version": "12",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "fPIC": "True",
                                    "shared": "False"
                                }
                            },
                            "vendor": false,
                            "dependencies": {
                                "5": {
                                    "ref": "automake/1.16.5",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "6": {
                                    "ref": "autoconf/2.71",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "7": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "12": {
                                    "ref": "automake/1.16.5",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "13": {
                                    "ref": "autoconf/2.71",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "14": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "19": {
                                    "ref": "gnu-config/cci.20210814",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "5": {
                            "ref": "automake/1.16.5#058bda3e21c36c9aa8425daf3c1faf50",
                            "id": "5",
                            "recipe": "Cache",
                            "package_id": "9a4eb3c8701508aa9458b1a73d0633783ecc2270",
                            "prev": "9719e51a6a62041af6a63e00eef35434",
                            "rrev": "058bda3e21c36c9aa8425daf3c1faf50",
                            "rrev_timestamp": 1688481772.751,
                            "prev_timestamp": 1688812270.617,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "automake",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": [
                                "GPL-2.0-or-later",
                                "GPL-3.0-or-later"
                            ],
                            "author": null,
                            "description": "Automake is a tool for automatically generating Makefile.in files compliant with the GNU Coding Standards.",
                            "homepage": "https://www.gnu.org/software/automake/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.16.5",
                            "topics": [
                                "autotools",
                                "configure",
                                "build"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/autom654153fb7a0c4/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "automake/1.16.5",
                            "info": {
                                "settings": {
                                    "os": "Linux"
                                }
                            },
                            "vendor": false,
                            "dependencies": {
                                "6": {
                                    "ref": "autoconf/2.71",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "7": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "9": {
                                    "ref": "autoconf/2.71",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "10": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "6": {
                            "ref": "autoconf/2.71#f9307992909d7fb3df459340f1932809",
                            "id": "6",
                            "recipe": "Cache",
                            "package_id": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "prev": "5b77f70c17ad1741f5845d4e468a347e",
                            "rrev": "f9307992909d7fb3df459340f1932809",
                            "rrev_timestamp": 1711983104.648,
                            "prev_timestamp": 1711983237.555,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "autoconf",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": [
                                "GPL-2.0-or-later",
                                "GPL-3.0-or-later"
                            ],
                            "author": null,
                            "description": "Autoconf is an extensible package of M4 macros that produce shell scripts to automatically configure software source code packages",
                            "homepage": "https://www.gnu.org/software/autoconf/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "2.71",
                            "topics": [
                                "configure",
                                "build"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/autoce8428bffabbfb/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "autoconf/2.71",
                            "info": {},
                            "vendor": false,
                            "dependencies": {
                                "7": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "8": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "7": {
                            "ref": "m4/1.4.19#b38ced39a01e31fef5435bc634461fd2",
                            "id": "7",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "cd8019a4f9b70880d548f7cc26569604",
                            "rrev": "b38ced39a01e31fef5435bc634461fd2",
                            "rrev_timestamp": 1700758725.451,
                            "prev_timestamp": 1700759976.449,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "m4",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "GPL-3.0-only",
                            "author": null,
                            "description": "GNU M4 is an implementation of the traditional Unix macro processor",
                            "homepage": "https://www.gnu.org/software/m4/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.4.19",
                            "topics": [
                                "macro",
                                "preprocessor"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/m4512cc8aabbc4c/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "m4/1.4.19",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "8": {
                            "ref": "m4/1.4.19#b38ced39a01e31fef5435bc634461fd2",
                            "id": "8",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "cd8019a4f9b70880d548f7cc26569604",
                            "rrev": "b38ced39a01e31fef5435bc634461fd2",
                            "rrev_timestamp": 1700758725.451,
                            "prev_timestamp": 1700759976.449,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "m4",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "GPL-3.0-only",
                            "author": null,
                            "description": "GNU M4 is an implementation of the traditional Unix macro processor",
                            "homepage": "https://www.gnu.org/software/m4/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.4.19",
                            "topics": [
                                "macro",
                                "preprocessor"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/m4512cc8aabbc4c/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "m4/1.4.19",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "9": {
                            "ref": "autoconf/2.71#f9307992909d7fb3df459340f1932809",
                            "id": "9",
                            "recipe": "Cache",
                            "package_id": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "prev": "5b77f70c17ad1741f5845d4e468a347e",
                            "rrev": "f9307992909d7fb3df459340f1932809",
                            "rrev_timestamp": 1711983104.648,
                            "prev_timestamp": 1711983237.555,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "autoconf",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": [
                                "GPL-2.0-or-later",
                                "GPL-3.0-or-later"
                            ],
                            "author": null,
                            "description": "Autoconf is an extensible package of M4 macros that produce shell scripts to automatically configure software source code packages",
                            "homepage": "https://www.gnu.org/software/autoconf/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "2.71",
                            "topics": [
                                "configure",
                                "build"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/autoce8428bffabbfb/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "autoconf/2.71",
                            "info": {},
                            "vendor": false,
                            "dependencies": {
                                "10": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "11": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "10": {
                            "ref": "m4/1.4.19#b38ced39a01e31fef5435bc634461fd2",
                            "id": "10",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "cd8019a4f9b70880d548f7cc26569604",
                            "rrev": "b38ced39a01e31fef5435bc634461fd2",
                            "rrev_timestamp": 1700758725.451,
                            "prev_timestamp": 1700759976.449,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "m4",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "GPL-3.0-only",
                            "author": null,
                            "description": "GNU M4 is an implementation of the traditional Unix macro processor",
                            "homepage": "https://www.gnu.org/software/m4/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.4.19",
                            "topics": [
                                "macro",
                                "preprocessor"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/m4512cc8aabbc4c/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "m4/1.4.19",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "11": {
                            "ref": "m4/1.4.19#b38ced39a01e31fef5435bc634461fd2",
                            "id": "11",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "cd8019a4f9b70880d548f7cc26569604",
                            "rrev": "b38ced39a01e31fef5435bc634461fd2",
                            "rrev_timestamp": 1700758725.451,
                            "prev_timestamp": 1700759976.449,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "m4",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "GPL-3.0-only",
                            "author": null,
                            "description": "GNU M4 is an implementation of the traditional Unix macro processor",
                            "homepage": "https://www.gnu.org/software/m4/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.4.19",
                            "topics": [
                                "macro",
                                "preprocessor"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/m4512cc8aabbc4c/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "m4/1.4.19",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "12": {
                            "ref": "automake/1.16.5#058bda3e21c36c9aa8425daf3c1faf50",
                            "id": "12",
                            "recipe": "Cache",
                            "package_id": "9a4eb3c8701508aa9458b1a73d0633783ecc2270",
                            "prev": "9719e51a6a62041af6a63e00eef35434",
                            "rrev": "058bda3e21c36c9aa8425daf3c1faf50",
                            "rrev_timestamp": 1688481772.751,
                            "prev_timestamp": 1688812270.617,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "automake",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": [
                                "GPL-2.0-or-later",
                                "GPL-3.0-or-later"
                            ],
                            "author": null,
                            "description": "Automake is a tool for automatically generating Makefile.in files compliant with the GNU Coding Standards.",
                            "homepage": "https://www.gnu.org/software/automake/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.16.5",
                            "topics": [
                                "autotools",
                                "configure",
                                "build"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/autom654153fb7a0c4/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "automake/1.16.5",
                            "info": {
                                "settings": {
                                    "os": "Linux"
                                }
                            },
                            "vendor": false,
                            "dependencies": {
                                "13": {
                                    "ref": "autoconf/2.71",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "14": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "16": {
                                    "ref": "autoconf/2.71",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "17": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "13": {
                            "ref": "autoconf/2.71#f9307992909d7fb3df459340f1932809",
                            "id": "13",
                            "recipe": "Cache",
                            "package_id": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "prev": "5b77f70c17ad1741f5845d4e468a347e",
                            "rrev": "f9307992909d7fb3df459340f1932809",
                            "rrev_timestamp": 1711983104.648,
                            "prev_timestamp": 1711983237.555,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "autoconf",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": [
                                "GPL-2.0-or-later",
                                "GPL-3.0-or-later"
                            ],
                            "author": null,
                            "description": "Autoconf is an extensible package of M4 macros that produce shell scripts to automatically configure software source code packages",
                            "homepage": "https://www.gnu.org/software/autoconf/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "2.71",
                            "topics": [
                                "configure",
                                "build"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/autoce8428bffabbfb/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "autoconf/2.71",
                            "info": {},
                            "vendor": false,
                            "dependencies": {
                                "14": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "15": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "14": {
                            "ref": "m4/1.4.19#b38ced39a01e31fef5435bc634461fd2",
                            "id": "14",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "cd8019a4f9b70880d548f7cc26569604",
                            "rrev": "b38ced39a01e31fef5435bc634461fd2",
                            "rrev_timestamp": 1700758725.451,
                            "prev_timestamp": 1700759976.449,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "m4",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "GPL-3.0-only",
                            "author": null,
                            "description": "GNU M4 is an implementation of the traditional Unix macro processor",
                            "homepage": "https://www.gnu.org/software/m4/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.4.19",
                            "topics": [
                                "macro",
                                "preprocessor"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/m4512cc8aabbc4c/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "m4/1.4.19",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "15": {
                            "ref": "m4/1.4.19#b38ced39a01e31fef5435bc634461fd2",
                            "id": "15",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "cd8019a4f9b70880d548f7cc26569604",
                            "rrev": "b38ced39a01e31fef5435bc634461fd2",
                            "rrev_timestamp": 1700758725.451,
                            "prev_timestamp": 1700759976.449,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "m4",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "GPL-3.0-only",
                            "author": null,
                            "description": "GNU M4 is an implementation of the traditional Unix macro processor",
                            "homepage": "https://www.gnu.org/software/m4/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.4.19",
                            "topics": [
                                "macro",
                                "preprocessor"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/m4512cc8aabbc4c/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "m4/1.4.19",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "16": {
                            "ref": "autoconf/2.71#f9307992909d7fb3df459340f1932809",
                            "id": "16",
                            "recipe": "Cache",
                            "package_id": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "prev": "5b77f70c17ad1741f5845d4e468a347e",
                            "rrev": "f9307992909d7fb3df459340f1932809",
                            "rrev_timestamp": 1711983104.648,
                            "prev_timestamp": 1711983237.555,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "autoconf",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": [
                                "GPL-2.0-or-later",
                                "GPL-3.0-or-later"
                            ],
                            "author": null,
                            "description": "Autoconf is an extensible package of M4 macros that produce shell scripts to automatically configure software source code packages",
                            "homepage": "https://www.gnu.org/software/autoconf/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "2.71",
                            "topics": [
                                "configure",
                                "build"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/autoce8428bffabbfb/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "autoconf/2.71",
                            "info": {},
                            "vendor": false,
                            "dependencies": {
                                "17": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                },
                                "18": {
                                    "ref": "m4/1.4.19",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "17": {
                            "ref": "m4/1.4.19#b38ced39a01e31fef5435bc634461fd2",
                            "id": "17",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "cd8019a4f9b70880d548f7cc26569604",
                            "rrev": "b38ced39a01e31fef5435bc634461fd2",
                            "rrev_timestamp": 1700758725.451,
                            "prev_timestamp": 1700759976.449,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "m4",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "GPL-3.0-only",
                            "author": null,
                            "description": "GNU M4 is an implementation of the traditional Unix macro processor",
                            "homepage": "https://www.gnu.org/software/m4/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.4.19",
                            "topics": [
                                "macro",
                                "preprocessor"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/m4512cc8aabbc4c/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "m4/1.4.19",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "18": {
                            "ref": "m4/1.4.19#b38ced39a01e31fef5435bc634461fd2",
                            "id": "18",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "cd8019a4f9b70880d548f7cc26569604",
                            "rrev": "b38ced39a01e31fef5435bc634461fd2",
                            "rrev_timestamp": 1700758725.451,
                            "prev_timestamp": 1700759976.449,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "m4",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "GPL-3.0-only",
                            "author": null,
                            "description": "GNU M4 is an implementation of the traditional Unix macro processor",
                            "homepage": "https://www.gnu.org/software/m4/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.4.19",
                            "topics": [
                                "macro",
                                "preprocessor"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/m4512cc8aabbc4c/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "m4/1.4.19",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "19": {
                            "ref": "gnu-config/cci.20210814#dc430d754f465e8c74463019672fb97b",
                            "id": "19",
                            "recipe": "Cache",
                            "package_id": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "prev": "22618e30bd9e326eb95e824dc90cc860",
                            "rrev": "dc430d754f465e8c74463019672fb97b",
                            "rrev_timestamp": 1701248168.479,
                            "prev_timestamp": 1701248306.606,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "gnu-config",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": [
                                "GPL-3.0-or-later",
                                "autoconf-special-exception"
                            ],
                            "author": null,
                            "description": "The GNU config.guess and config.sub scripts",
                            "homepage": "https://savannah.gnu.org/projects/config/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "cci.20210814",
                            "topics": [
                                "gnu",
                                "config",
                                "autotools",
                                "canonical",
                                "host",
                                "build",
                                "target",
                                "triplet"
                            ],
                            "package_type": "build-scripts",
                            "languages": [],
                            "settings": {},
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/gnu-cbb47279af5340/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "gnu-config/cci.20210814",
                            "info": {},
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "20": {
                            "ref": "pkgconf/2.1.0#27f44583701117b571307cf5b5fe5605",
                            "id": "20",
                            "recipe": "Cache",
                            "package_id": "c0b621fd4b3199fe05075171573398833dba85f4",
                            "prev": "74a82dec52448dda20253a19d65965c7",
                            "rrev": "27f44583701117b571307cf5b5fe5605",
                            "rrev_timestamp": 1701537936.436,
                            "prev_timestamp": 1701538376.351,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "pkgconf",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "ISC",
                            "author": null,
                            "description": "package compiler and linker metadata toolkit",
                            "homepage": "https://git.sr.ht/~kaniini/pkgconf",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true,
                                "enable_lib": false
                            },
                            "options_description": null,
                            "version": "2.1.0",
                            "topics": [
                                "build",
                                "configuration"
                            ],
                            "package_type": "unknown",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "enable_lib": "False"
                            },
                            "options_definitions": {
                                "enable_lib": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/pkgco39164e4b4e12d/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "pkgconf/2.1.0",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "enable_lib": "False"
                                }
                            },
                            "vendor": false,
                            "dependencies": {
                                "21": {
                                    "ref": "meson/1.2.2",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "22": {
                                    "ref": "ninja/1.11.1",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "21": {
                            "ref": "meson/1.2.2#04bdfb85d665c82b08a3510aee3ffd19",
                            "id": "21",
                            "recipe": "Cache",
                            "package_id": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "prev": "97f4a23dd2d942f83e5344b1ca496ce7",
                            "rrev": "04bdfb85d665c82b08a3510aee3ffd19",
                            "rrev_timestamp": 1702568761.764,
                            "prev_timestamp": 1702572748.354,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "meson",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "Apache-2.0",
                            "author": null,
                            "description": "Meson is a project to create the best possible next-generation build system",
                            "homepage": "https://github.com/mesonbuild/meson",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.2.2",
                            "topics": [
                                "meson",
                                "mesonbuild",
                                "build-system"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {},
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/meson9aba974547f5b/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "meson/1.2.2",
                            "info": {},
                            "vendor": false,
                            "dependencies": {
                                "22": {
                                    "ref": "ninja/1.11.1",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "22": {
                            "ref": "ninja/1.11.1#77587f8c8318662ac8e5a7867eb4be21",
                            "id": "22",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "60e6fc0f973babfbed66a66af22a4f02",
                            "rrev": "77587f8c8318662ac8e5a7867eb4be21",
                            "rrev_timestamp": 1684431244.21,
                            "prev_timestamp": 1684431632.795,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "ninja",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "Apache-2.0",
                            "author": null,
                            "description": "Ninja is a small build system with a focus on speed",
                            "homepage": "https://github.com/ninja-build/ninja",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.11.1",
                            "topics": [
                                "ninja",
                                "build"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/ninja19c9f8e277acc/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "ninja/1.11.1",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "23": {
                            "ref": "libxslt/1.1.34#46843838a3bd81997cd66a2dcd320ed6",
                            "id": "23",
                            "recipe": "Cache",
                            "package_id": "00211d5dad2f276aa2b97b3332f900e3f957d620",
                            "prev": null,
                            "rrev": "46843838a3bd81997cd66a2dcd320ed6",
                            "rrev_timestamp": 1713421149.634,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": "Missing",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "libxslt",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "MIT",
                            "author": null,
                            "description": "libxslt is a software library implementing XSLT processor, based on libxml2",
                            "homepage": "https://xmlsoft.org",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true,
                                "debugger": false,
                                "crypto": false,
                                "profiler": false,
                                "plugins": false
                            },
                            "options_description": null,
                            "version": "1.1.34",
                            "topics": [
                                "xslt",
                                "processor"
                            ],
                            "package_type": "static-library",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "crypto": "False",
                                "debugger": "False",
                                "fPIC": "True",
                                "plugins": "False",
                                "profiler": "False",
                                "shared": "False"
                            },
                            "options_definitions": {
                                "shared": [
                                    "True",
                                    "False"
                                ],
                                "fPIC": [
                                    "True",
                                    "False"
                                ],
                                "debugger": [
                                    "True",
                                    "False"
                                ],
                                "crypto": [
                                    "True",
                                    "False"
                                ],
                                "profiler": [
                                    "True",
                                    "False"
                                ],
                                "plugins": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/libxsd2269e64a9090/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "libxslt/1.1.34",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "compiler": "gcc",
                                    "compiler.version": "12",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "crypto": "False",
                                    "debugger": "False",
                                    "fPIC": "True",
                                    "plugins": "False",
                                    "profiler": "False",
                                    "shared": "False"
                                },
                                "requires": [
                                    "libxml2/2.11.Z",
                                    "zlib/1.3.Z",
                                    "libiconv/1.17.Z"
                                ]
                            },
                            "vendor": false,
                            "dependencies": {
                                "24": {
                                    "ref": "libxml2/2.11.6",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": true,
                                    "transitive_libs": true,
                                    "headers": true,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                },
                                "25": {
                                    "ref": "zlib/1.3.1",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": false,
                                    "transitive_headers": true,
                                    "transitive_libs": true,
                                    "headers": false,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                },
                                "26": {
                                    "ref": "libiconv/1.17",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": false,
                                    "transitive_headers": true,
                                    "transitive_libs": true,
                                    "headers": true,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "24": {
                            "ref": "libxml2/2.11.6#41c14895baba105865cb22ecaf948115",
                            "id": "24",
                            "recipe": "Cache",
                            "package_id": "2363b29014eddd6edddabfd550d1cf9f0bb6d30e",
                            "prev": null,
                            "rrev": "41c14895baba105865cb22ecaf948115",
                            "rrev_timestamp": 1703682489.517,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "libxml2",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "MIT",
                            "author": null,
                            "description": "libxml2 is a software library for parsing XML documents",
                            "homepage": "https://gitlab.gnome.org/GNOME/libxml2/-/wikis/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true,
                                "include_utils": true,
                                "c14n": true,
                                "catalog": true,
                                "docbook": true,
                                "ftp": true,
                                "http": true,
                                "html": true,
                                "iconv": true,
                                "icu": false,
                                "iso8859x": true,
                                "legacy": true,
                                "mem-debug": false,
                                "output": true,
                                "pattern": true,
                                "push": true,
                                "python": false,
                                "reader": true,
                                "regexps": true,
                                "run-debug": false,
                                "sax1": true,
                                "schemas": true,
                                "schematron": true,
                                "threads": true,
                                "tree": true,
                                "valid": true,
                                "writer": true,
                                "xinclude": true,
                                "xpath": true,
                                "xptr": true,
                                "zlib": true,
                                "lzma": false
                            },
                            "options_description": null,
                            "version": "2.11.6",
                            "topics": [
                                "xml",
                                "parser",
                                "validation"
                            ],
                            "package_type": "static-library",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "c14n": "True",
                                "catalog": "True",
                                "fPIC": "True",
                                "ftp": "True",
                                "html": "True",
                                "http": "True",
                                "iconv": "True",
                                "icu": "False",
                                "include_utils": "True",
                                "iso8859x": "True",
                                "legacy": "True",
                                "lzma": "False",
                                "mem-debug": "False",
                                "output": "True",
                                "pattern": "True",
                                "push": "True",
                                "python": "False",
                                "reader": "True",
                                "regexps": "True",
                                "sax1": "True",
                                "schemas": "True",
                                "schematron": "True",
                                "shared": "False",
                                "threads": "True",
                                "tree": "True",
                                "valid": "True",
                                "writer": "True",
                                "xinclude": "True",
                                "xpath": "True",
                                "xptr": "True",
                                "zlib": "True"
                            },
                            "options_definitions": {
                                "shared": [
                                    "True",
                                    "False"
                                ],
                                "fPIC": [
                                    "True",
                                    "False"
                                ],
                                "include_utils": [
                                    "True",
                                    "False"
                                ],
                                "c14n": [
                                    "True",
                                    "False"
                                ],
                                "catalog": [
                                    "True",
                                    "False"
                                ],
                                "ftp": [
                                    "True",
                                    "False"
                                ],
                                "http": [
                                    "True",
                                    "False"
                                ],
                                "html": [
                                    "True",
                                    "False"
                                ],
                                "iconv": [
                                    "True",
                                    "False"
                                ],
                                "icu": [
                                    "True",
                                    "False"
                                ],
                                "iso8859x": [
                                    "True",
                                    "False"
                                ],
                                "legacy": [
                                    "True",
                                    "False"
                                ],
                                "mem-debug": [
                                    "True",
                                    "False"
                                ],
                                "output": [
                                    "True",
                                    "False"
                                ],
                                "pattern": [
                                    "True",
                                    "False"
                                ],
                                "push": [
                                    "True",
                                    "False"
                                ],
                                "python": [
                                    "True",
                                    "False"
                                ],
                                "reader": [
                                    "True",
                                    "False"
                                ],
                                "regexps": [
                                    "True",
                                    "False"
                                ],
                                "sax1": [
                                    "True",
                                    "False"
                                ],
                                "schemas": [
                                    "True",
                                    "False"
                                ],
                                "schematron": [
                                    "True",
                                    "False"
                                ],
                                "threads": [
                                    "True",
                                    "False"
                                ],
                                "tree": [
                                    "True",
                                    "False"
                                ],
                                "valid": [
                                    "True",
                                    "False"
                                ],
                                "writer": [
                                    "True",
                                    "False"
                                ],
                                "xinclude": [
                                    "True",
                                    "False"
                                ],
                                "xpath": [
                                    "True",
                                    "False"
                                ],
                                "xptr": [
                                    "True",
                                    "False"
                                ],
                                "zlib": [
                                    "True",
                                    "False"
                                ],
                                "lzma": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/libxmbb39269f92c50/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "libxml2/2.11.6",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "compiler": "gcc",
                                    "compiler.version": "12",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "c14n": "True",
                                    "catalog": "True",
                                    "fPIC": "True",
                                    "ftp": "True",
                                    "html": "True",
                                    "http": "True",
                                    "iconv": "True",
                                    "icu": "False",
                                    "include_utils": "True",
                                    "iso8859x": "True",
                                    "legacy": "True",
                                    "lzma": "False",
                                    "mem-debug": "False",
                                    "output": "True",
                                    "pattern": "True",
                                    "push": "True",
                                    "python": "False",
                                    "reader": "True",
                                    "regexps": "True",
                                    "sax1": "True",
                                    "schemas": "True",
                                    "schematron": "True",
                                    "shared": "False",
                                    "threads": "True",
                                    "tree": "True",
                                    "valid": "True",
                                    "writer": "True",
                                    "xinclude": "True",
                                    "xpath": "True",
                                    "xptr": "True",
                                    "zlib": "True"
                                },
                                "requires": [
                                    "zlib/1.3.Z",
                                    "libiconv/1.17.Z"
                                ]
                            },
                            "vendor": false,
                            "dependencies": {
                                "25": {
                                    "ref": "zlib/1.3.1",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": true,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                },
                                "26": {
                                    "ref": "libiconv/1.17",
                                    "run": false,
                                    "libs": true,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": true,
                                    "transitive_libs": true,
                                    "headers": true,
                                    "package_id_mode": "minor_mode",
                                    "visible": true
                                },
                                "27": {
                                    "ref": "pkgconf/2.1.0",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "25": {
                            "ref": "zlib/1.3.1#f52e03ae3d251dec704634230cd806a2",
                            "id": "25",
                            "recipe": "Cache",
                            "package_id": "5bc851010eb7b707e5cb2e24cb8ccf0f27989fa9",
                            "prev": null,
                            "rrev": "f52e03ae3d251dec704634230cd806a2",
                            "rrev_timestamp": 1708593606.497,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "zlib",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "Zlib",
                            "author": null,
                            "description": "A Massively Spiffy Yet Delicately Unobtrusive Compression Library (Also Free, Not to Mention Unencumbered by Patents)",
                            "homepage": "https://zlib.net",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true
                            },
                            "options_description": null,
                            "version": "1.3.1",
                            "topics": [
                                "zlib",
                                "compression"
                            ],
                            "package_type": "static-library",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "fPIC": "True",
                                "shared": "False"
                            },
                            "options_definitions": {
                                "shared": [
                                    "True",
                                    "False"
                                ],
                                "fPIC": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/zlib41bd3946e7341/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "zlib/1.3.1",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "compiler": "gcc",
                                    "compiler.version": "12",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "fPIC": "True",
                                    "shared": "False"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "26": {
                            "ref": "libiconv/1.17#73fefc1b696e069df90fd1d18aa63edd",
                            "id": "26",
                            "recipe": "Cache",
                            "package_id": "5bc851010eb7b707e5cb2e24cb8ccf0f27989fa9",
                            "prev": null,
                            "rrev": "73fefc1b696e069df90fd1d18aa63edd",
                            "rrev_timestamp": 1707122814.387,
                            "prev_timestamp": null,
                            "remote": null,
                            "binary_remote": null,
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "libiconv",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "LGPL-2.1-or-later",
                            "author": null,
                            "description": "Convert text to and from Unicode",
                            "homepage": "https://www.gnu.org/software/libiconv/",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true
                            },
                            "options_description": null,
                            "version": "1.17",
                            "topics": [
                                "iconv",
                                "text",
                                "encoding",
                                "locale",
                                "unicode",
                                "conversion"
                            ],
                            "package_type": "static-library",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "fPIC": "True",
                                "shared": "False"
                            },
                            "options_definitions": {
                                "shared": [
                                    "True",
                                    "False"
                                ],
                                "fPIC": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/libic9912aaea08621/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "libiconv/1.17",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "compiler": "gcc",
                                    "compiler.version": "12",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "fPIC": "True",
                                    "shared": "False"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        },
                        "27": {
                            "ref": "pkgconf/2.1.0#27f44583701117b571307cf5b5fe5605",
                            "id": "27",
                            "recipe": "Cache",
                            "package_id": "c0b621fd4b3199fe05075171573398833dba85f4",
                            "prev": "74a82dec52448dda20253a19d65965c7",
                            "rrev": "27f44583701117b571307cf5b5fe5605",
                            "rrev_timestamp": 1701537936.436,
                            "prev_timestamp": 1701538376.351,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "pkgconf",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "ISC",
                            "author": null,
                            "description": "package compiler and linker metadata toolkit",
                            "homepage": "https://git.sr.ht/~kaniini/pkgconf",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": {
                                "shared": false,
                                "fPIC": true,
                                "enable_lib": false
                            },
                            "options_description": null,
                            "version": "2.1.0",
                            "topics": [
                                "build",
                                "configuration"
                            ],
                            "package_type": "unknown",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {
                                "enable_lib": "False"
                            },
                            "options_definitions": {
                                "enable_lib": [
                                    "True",
                                    "False"
                                ]
                            },
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/pkgco39164e4b4e12d/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "pkgconf/2.1.0",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                },
                                "options": {
                                    "enable_lib": "False"
                                }
                            },
                            "vendor": false,
                            "dependencies": {
                                "28": {
                                    "ref": "meson/1.2.2",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                },
                                "29": {
                                    "ref": "ninja/1.11.1",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": false,
                                    "build": true,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": false
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "28": {
                            "ref": "meson/1.2.2#04bdfb85d665c82b08a3510aee3ffd19",
                            "id": "28",
                            "recipe": "Cache",
                            "package_id": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                            "prev": "97f4a23dd2d942f83e5344b1ca496ce7",
                            "rrev": "04bdfb85d665c82b08a3510aee3ffd19",
                            "rrev_timestamp": 1702568761.764,
                            "prev_timestamp": 1702572748.354,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "meson",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "Apache-2.0",
                            "author": null,
                            "description": "Meson is a project to create the best possible next-generation build system",
                            "homepage": "https://github.com/mesonbuild/meson",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.2.2",
                            "topics": [
                                "meson",
                                "mesonbuild",
                                "build-system"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {},
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/meson9aba974547f5b/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "meson/1.2.2",
                            "info": {},
                            "vendor": false,
                            "dependencies": {
                                "29": {
                                    "ref": "ninja/1.11.1",
                                    "run": true,
                                    "libs": false,
                                    "skip": false,
                                    "test": false,
                                    "force": false,
                                    "direct": true,
                                    "build": false,
                                    "transitive_headers": null,
                                    "transitive_libs": null,
                                    "headers": false,
                                    "package_id_mode": null,
                                    "visible": true
                                }
                            },
                            "context": "build",
                            "test": false
                        },
                        "29": {
                            "ref": "ninja/1.11.1#77587f8c8318662ac8e5a7867eb4be21",
                            "id": "29",
                            "recipe": "Cache",
                            "package_id": "3593751651824fb813502c69c971267624ced41a",
                            "prev": "60e6fc0f973babfbed66a66af22a4f02",
                            "rrev": "77587f8c8318662ac8e5a7867eb4be21",
                            "rrev_timestamp": 1684431244.21,
                            "prev_timestamp": 1684431632.795,
                            "remote": null,
                            "binary_remote": "conancenter",
                            "build_id": null,
                            "binary": "Skip",
                            "invalid_build": false,
                            "info_invalid": null,
                            "name": "ninja",
                            "user": null,
                            "channel": null,
                            "url": "https://github.com/conan-io/conan-center-index",
                            "license": "Apache-2.0",
                            "author": null,
                            "description": "Ninja is a small build system with a focus on speed",
                            "homepage": "https://github.com/ninja-build/ninja",
                            "build_policy": null,
                            "upload_policy": null,
                            "revision_mode": "hash",
                            "provides": null,
                            "deprecated": null,
                            "win_bash": null,
                            "win_bash_run": null,
                            "default_options": null,
                            "options_description": null,
                            "version": "1.11.1",
                            "topics": [
                                "ninja",
                                "build"
                            ],
                            "package_type": "application",
                            "languages": [],
                            "settings": {
                                "os": "Linux",
                                "arch": "x86_64",
                                "compiler": "gcc",
                                "compiler.cppstd": "gnu17",
                                "compiler.libcxx": "libstdc++11",
                                "compiler.version": "12",
                                "build_type": "Release"
                            },
                            "options": {},
                            "options_definitions": {},
                            "generators": [],
                            "python_requires": null,
                            "system_requires": {},
                            "recipe_folder": "/home/reto/.conan2/p/ninja19c9f8e277acc/e",
                            "source_folder": null,
                            "build_folder": null,
                            "generators_folder": null,
                            "package_folder": null,
                            "cpp_info": {
                                "root": {
                                    "includedirs": [
                                        "include"
                                    ],
                                    "srcdirs": null,
                                    "libdirs": [
                                        "lib"
                                    ],
                                    "resdirs": null,
                                    "bindirs": [
                                        "bin"
                                    ],
                                    "builddirs": null,
                                    "frameworkdirs": null,
                                    "system_libs": null,
                                    "frameworks": null,
                                    "libs": null,
                                    "defines": null,
                                    "cflags": null,
                                    "cxxflags": null,
                                    "sharedlinkflags": null,
                                    "exelinkflags": null,
                                    "objects": null,
                                    "sysroot": null,
                                    "requires": null,
                                    "properties": null
                                }
                            },
                            "conf_info": {},
                            "label": "ninja/1.11.1",
                            "info": {
                                "settings": {
                                    "os": "Linux",
                                    "arch": "x86_64",
                                    "build_type": "Release"
                                }
                            },
                            "vendor": false,
                            "dependencies": {},
                            "context": "build",
                            "test": false
                        }
                    },
                    "root": {
                        "0": "None"
                    },
                    "overrides": {},
                    "resolved_ranges": {
                        "openssl/[>=1.1 <4]": "openssl/3.2.2",
                        "zlib/[>=1.2.11 <2]": "zlib/1.3.1"
                    },
                    "replaced_requires": {},
                    "error": null
                }
            }
            """.trimIndent()

        val conanGraph = parseGraph(jsonString)
    }
})
