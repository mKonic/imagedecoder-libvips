<div align="center">

<h1 align="center"> imagedecoder </h1>

[![Release build](https://img.shields.io/github/actions/workflow/status/mKonic/imagedecoder-libvips/release.yml?labelColor=27303D&label=Release&labelColor=06599d&color=043b69)](https://github.com/mKonic/imagedecoder-libvips/actions/workflows/release.yml)
[![Release](https://img.shields.io/github/v/release/mKonic/imagedecoder-libvips.svg?maxAge=3600&label=Release&labelColor=06599d&color=043b69)](https://github.com/mKonic/imagedecoder-libvips/releases/latest)
[![License: MIT](https://img.shields.io/github/license/mKonic/imagedecoder-libvips?labelColor=27303D&color=0877d2)](/LICENSE)

<div align="left">

An image decoder for Android built on libvips: JPEG, PNG, WebP, GIF, TIFF, HEIF, JPEG XL and
JPEG 2000, with HDR and gain maps. This fork of
[mpreg-ca/imagedecoder-libvips](https://github.com/mpreg-ca/imagedecoder-libvips) carries the fixes
[Komikku](https://github.com/mKonic/komikku) needs ahead of them landing upstream, and proposes the
ones of general interest back.

## Use

Releases are attached to their tag rather than published to Maven Central, so they resolve through
an ivy repository over the release assets.

```kotlin
// settings.gradle.kts
exclusiveContent {
    forRepository {
        ivy("https://github.com/mKonic/imagedecoder-libvips/releases/download") {
            patternLayout {
                ivy("v[revision]/ivy-[revision].xml")
                artifact("v[revision]/[artifact]-[revision].[ext]")
            }
            metadataSources { ivyDescriptor() }
        }
    }
    filter { includeModule("ca.mpreg", "imagedecoder") }
}

// build.gradle.kts
implementation("ca.mpreg:imagedecoder:1.0.0")
```

The coordinates are upstream's, so pointing at a different repository is all it takes to build
against upstream instead.

## License

MIT, as upstream. See [LICENSE](./LICENSE).
