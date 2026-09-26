plugins {
    alias(libs.plugins.android.library)
    id("com.vanniktech.maven.publish") version "0.36.0"
}

// The fork's version is its last semver tag: scripts/version.sh is the one source. Releasing is
// tagging, and the release workflow publishes the AAR with an ivy descriptor beside it.
val tag: String = providers.exec {
    commandLine("bash", rootProject.file("scripts/version.sh").path, "name")
}.standardOutput.asText.map { it.trim().removePrefix("v") }.getOrElse("unknown")

android {
    namespace = "ca.mpreg.imagedecoder"
    compileSdk = 37

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        externalNativeBuild {
            cmake {
                cppFlags("-O3 -flto")
                targets("ep_imagedecoder")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // The native build is libvips and every codec from source; a debug variant would be a second one.
    testBuildType = "release"

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
}

/**
 * The ivy descriptor hosts resolve this AAR through from a GitHub release. Nothing to list: the
 * native libraries are all linked into the one .so.
 */
val writeIvyDescriptor by tasks.registering {
    // A local, not the script's own property, which the configuration cache cannot serialise.
    val version = tag
    val descriptor = layout.buildDirectory.file("outputs/ivy/ivy-$version.xml")
    inputs.property("version", version)
    outputs.file(descriptor)
    doLast {
        descriptor.get().asFile.apply { parentFile.mkdirs() }.writeText(
            """
            |<?xml version="1.0" encoding="UTF-8"?>
            |<ivy-module version="2.0">
            |    <info organisation="ca.mpreg" module="imagedecoder" revision="$version"/>
            |    <configurations>
            |        <conf name="default"/>
            |    </configurations>
            |    <publications>
            |        <artifact name="imagedecoder" type="aar" ext="aar" conf="default"/>
            |    </publications>
            |</ivy-module>
            |""".trimMargin()
        )
    }
}

afterEvaluate {
    mavenPublishing {
        coordinates("ca.mpreg", "imagedecoder", tag)

        pom {
            name.set("imagedecoder")
            description.set("imagedecoder")
            inceptionYear.set("2026")
            url.set("https://github.com/mpreg-ca/imagedecoder")
            licenses {
                license {
                    name.set("MIT License")
                    url.set("https://opensource.org")
                    distribution.set("repo")
                }
            }
            developers {
                developer {
                    id.set("wwww-wwww")
                    name.set("w")
                    url.set("https://github.com/wwww-wwww/")
                }
            }
            scm {
                url.set("https://github.com/mpreg-ca/imagedecoder/")
                connection.set("scm:git:git://github.com/mpreg-ca/imagedecoder.git")
                developerConnection.set("scm:git:ssh://git@github.com/mpreg-ca/imagedecoder.git")
            }
        }

        publishToMavenCentral(automaticRelease = true)
        signAllPublications()
    }
}
