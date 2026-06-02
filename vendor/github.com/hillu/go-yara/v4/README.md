![Logo](/goyara-logo.png)

# go-yara

[![PkgGoDev](https://pkg.go.dev/badge/github.com/hillu/go-yara/v4)](https://pkg.go.dev/github.com/hillu/go-yara/v4)
[![buildtest](https://github.com/hillu/go-yara/actions/workflows/buildtest.yml/badge.svg)](https://github.com/hillu/go-yara/actions/workflows/buildtest.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/hillu/go-yara)](https://goreportcard.com/report/github.com/hillu/go-yara)

Go bindings for [YARA](https://virustotal.github.io/yara/), staying as
close as sensible to the library's C-API while taking inspiration from
the `yara-python` implementation.

## Build/Installation

On Unix-like systems, _libyara_ version 4.3, corresponding header files,
and _pkg-config_ must be installed. Adding _go-yara_ v4 to a project
with Go Modules enabled, simply add the proper dependency…

``` go
import "github.com/hillu/go-yara/v4"
```

…and rebuild your package.

If _libyara_ has been installed to a custom location, the
`PKG_CONFIG_PATH` environment variable can be used to point
_pkg-config_ at the right `yara.pc` file.

For anything more complicated, refer to the "Build Tags" section
below. Instructions for cross-building _go-yara_ for different
operating systems or architectures can be found in
[README.cross-building.md](README.cross-building.md).

To build _go-yara_ on Windows, a GCC-based build environment is
required, preferably one that includes _pkg-config_. The 32-bit and
64-bit MinGW environments provided by the [MSYS2](https://msys2.org/)
provide such an environment.

## Build Tags

### Static builds

The build tag `yara_static` can be used to tell the Go toolchain to
run _pkg-config_ with the `--static` switch. This is not enough for a
static build; the appropriate linker flags (e.g. `-extldflags
"-static"`) still need to be passed to the _go_ tool.

### Building without _pkg-config_

The build tag `yara_no_pkg_config` can be used to tell the Go toolchain not
to use _pkg-config_'s output. In this case, any compiler or linker
flags have to be set via the `CGO_CFLAGS` and `CGO_LDFLAGS`
environment variables, e.g.:

```
export CGO_CFLAGS="-I${YARA_SRC}/libyara/include"
export CGO_LDFLAGS="-L${YARA_SRC}/libyara/.libs -lyara"
go install -tags yara_no_pkg_config github.com/hillu/go-yara
```

If _libyara_ has been linked against other libraries (e.g.
_libcrypto_, _libmagic_) and a static build is performed, these
libraries also need to be added to `CGO_LDFLAGS`.

## YARA 4.1.x vs. earlier versions

This version of _go-yara_ can only be used with YARA 4.3 or later.

Version of _go-yara_ compatible with YARA 4.1.x are available via the
`v4.2.x` branch or tagged `v4.2.*` releases.

Version of _go-yara_ compatible with YARA 4.1.x are available via the
`v4.1.x` branch or tagged `v4.1.*` releases.

Version of _go-yara_ compatible with YARA 4.0.x are available via the
`v4.0.x` branch or tagged `v4.0.*` releases.

Versions of _go-yara_ compatible with YARA 3.11 are available via the
`v3.x` branch or tagged `v3.*` releases.

Versions of _go-yara_ compatible with earlier 3.x versions of YARA are
available via the `v1.x` branch or tagged `v1.*` releases.

## License

BSD 2-clause, see LICENSE file in the source distribution.

## Author

Hilko Bengen <<bengen@hilluzination.de>>
