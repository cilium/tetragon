# Cross-building _go-yara_

_go-yara_ can be cross-built for a different CPU
architecture/operating system platform, provided a C cross-compiler
for the target platform is available to be used by the _cgo_ tool.

After the _yara_ library has been built using the proper C
cross-compiler through the usual `configure / make / make install`
steps, _go-yara_ can be built and installed. The following environment
variables need to be set when running `go build` or `go install`:

- `GOOS`, `GOARCH` indicate the cross compilation target.
- `CGO_ENABLED` has to be set to 1 beacuse it defaults to 0 when
  cross-compiling.
- `CC` may have to be set to point to the C cross compiler. (It
  defaults to the system C compiler, usually gcc).
- `PKG_CONFIG_PATH` may have to be set to point to the _pkg-config_
  directory where the `yara.pc` file has been
  installed. (Alternatively, the `yara_no_pkg_config` build tag can be
  used together with `CGO_CFLAGS` and `CGO_LDFLAGS` environment
  variables.)

For the examples below, YARA is built out-of-tree, i.e. the build
artifacts are placed into a separate directory referred to by the
`YARA_BUILD_*` shell variables. `YARA_SRC` refers to the YARA source
directory. The `PREFIX_*` shell variables refer to target directory
for the `make install` step.

Since the MinGW environments provided by [MSYS2](https://msys2.org/)
are technically cross-building environments, similar steps have to be
taken, see below.

## Example: Building an entirely static Linux binary (musl-libc)

Because binaries that are linked statically with GNU libc are not
entirely portable [musl libc](https://www.musl-libc.org/) can be used
instead. (Sadly, it does not seem to be possible to cross-build for
different architctures using the standard `musl-gcc.specs` file.)

On a Debian-based system, install `musl-tools`.

Build _libyara_ and [`_examples/simple-yara`](_examples/simple-yara):
``` shell
( cd ${YARA_BUILD_LINUX_MUSL} && \
  ${YARA_SRC}/configure CC=musl-gcc --prefix=${PREFIX_LINUX_MUSL})
make -C ${YARA_BUILD_LINUX_MUSL} install

GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
  CC=musl-gcc \
  PKG_CONFIG_PATH=${PREFIX_LINUX_MUSL}/lib/pkgconfig \
      go build -ldflags '-extldflags "-static"' -tags yara_static -o simple-yara-musl ./_examples/simple-yara
```

## Example: Cross-building for Windows

On a Debian-based system, install the MinGW C compiler
`gcc-mingw-w64-i686`, `gcc-mingw-w64-x86-64` for Win32, Win64,
respectively.

Build _libyara_ and [`_examples/simple-yara`](_examples/simple-yara) for Win32:
``` shell
( cd ${YARA_BUILD_WIN32} && \
  ${YARA_SRC}/configure --host=i686-w64-mingw32 --prefix=${PREFIX_WIN32} )
make -C ${YARA_BUILD_WIN32} install

GOOS=windows GOARCH=386 CGO_ENABLED=1 \
  CC=i686-w64-mingw32-gcc \
  PKG_CONFIG_PATH=${PREFIX_WIN32}/lib/pkgconfig \
      go build -ldflags '-extldflags "-static"' -tags yara_static -o simple-yara-w32.exe ./_examples/simple-yara
```

Build _libyara_ and [`_examples/simple-yara`](_examples/simple-yara) for Win64:
``` shell
( cd ${YARA_BUILD_WIN64} && \
  ${YARA_SRC}/configure --host=x86_64-w64-mingw32 --prefix=${PREFIX_WIN64} )
make -C ${YARA_BUILD_WIN64} install

GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
  CC=x86_64-w64-mingw32-gcc \
  PKG_CONFIG_PATH=${PREFIX_WIN64}/lib/pkgconfig \
      go build -ldflags '-extldflags "-static"' -tags yara_static -o simple-yara-w64.exe ./_examples/simple-yara
```

## Example: Building on Windows, using MSYS2

This example assumes that [MSYS2](https://msys2.org/) has been
installed to `C:\msys64`. The following packages have to be installed:
- autoconf
- automake
- libtool
- mingw-w64-{x86_64,i686}-gcc
- mingw-w64-{x86_64,i686}-make
- mingw-w64-{x86_64,i686}-pkgconf

While MSYS2 contains usable Go compilers, the [official
distribution](https://golang.org/dl) is used here.

Build _libyara_ and [`_examples/simple-yara`](_examples/simple-yara) for Win32:

- At the MinGW 32 prompt:
  ```
  cd ${YARA_BUILD_WIN32} && ${YARA_SRC}/configure
  make -C ${YARA_BUILD_WIN32} install
  ```
- At the CMD or Powershell prompt:
  ```
  set PATH=%PATH%;C:\msys64\mingw32\bin
  set CGO_ENABLED=1
  set GOARCH=386
  go build -ldflags "-extldflags=-static" -tags yara_static -o simple-yara-w32.exe .\_examples\simple-yara
  ```

Build _libyara_ and [`_examples/simple-yara`](_examples/simple-yara) for Win64:

- At the MinGW 64 prompt:
  ```
  cd ${YARA_BUILD_WIN64} && ${YARA_SRC}/configure
  make -C ${YARA_BUILD_WIN64} install
  ```
- At the CMD or Powershell prompt:
  ```
  set PATH=%PATH%;C:\msys64\mingw64\bin
  set CGO_ENABLED=1
  set GOARCH=amd64
  go build -ldflags "-extldflags=-static" -tags yara_static -o simple-yara-w64.exe .\_examples\simple-yara
  ```
