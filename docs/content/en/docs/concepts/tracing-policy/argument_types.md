---
title: "Argument types"
weight: 2
description: "Argument types for data retrieval"
---

Each argument definition specifies data type to be retrieved from kernel
argument. The list contains simple POD types and several complex kernel
objects that are represented by extracted data type.

List of described data types:
- [`sint8, int8`](#int8)
- [`uint8`](#uint8)
- [`sint16, int16`](#int16)
- [`uint16`](#uint16)
- [`int, sint32, int32`](#int)
- [`uint32`](#uint32)
- [`long, sint64, int64`](#long)
- [`ulong, uint64, size_t`](#ulong)
- [`string`](#string)
- [`skb`](#skb)
- [`sock`](#sock)
- [`char_buf`](#char_buf)
- [`char_iovec`](#char_iovec)
- [`filename`](#filename)
- [`fd`](#fd)
- [`cred`](#cred)
- [`const_buf`](#const_buf)
- [`nop`](#nop)
- [`bpf_attr`](#bpf_attr)
- [`perf_event`](#perf_event)
- [`bpf_map`](#bpf_map)
- [`bpf_prog`](#bpf_prog)
- [`user_namespace`](#user_namespace)
- [`capability`](#capability)
- [`kiocb`](#kiocb)
- [`iov_iter`](#iov_iter)
- [`load_info`](#load_info)
- [`module`](#module)
- [`syscall64`](#syscall64)
- [`kernel_cap_t`](#kernel_cap_t)
- [`cap_inheritable`](#cap_inheritable)
- [`cap_permitted`](#cap_permitted)
- [`cap_effective`](#cap_effective)
- [`linux_binprm`](#linux_binprm)
- [`data_loc`](#data_loc)
- [`net_device`](#net_device)
- [`sockaddr`](#sockaddr)
- [`socket`](#socket)
- [`file`](#file)
- [`dentry`](#dentry)
- [`path`](#path)

{{< note >}}
All integer types (`int8`, `uint8`, `int16`, `uint16`, `int32`, `uint32`, `int64`, `uint64`)
support `Equal`, `NotEqual`, `GT`, `LT`, and `Mask` operators in `matchArgs`.
{{< /note >}}

<a name="int8"></a>

## `sint8, int8`

The data type extracts 8-bit signed value.

## `uint8`

The data type extracts 8-bit unsigned value.

<a name="int16"></a>

## `sint16, int16`

The data type extracts 16-bit signed value.

## `uint16`

The data type extracts 16-bit unsigned value.

<a name="int"></a>

## `int, sint32, int32`

The data type extracts 32-bit signed value.

## `uint32`

The data type extracts 32-bit unsigned value.

<a name="long"></a>

## `long, sint64, int64`

The data type extracts 64-bit signed value.

<a name="ulong"></a>

## `ulong, uint64, size_t`

The data type extracts 64-bit unsigned value.

## `string`

The data type extracts string terminated with zero byte.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators.

## `skb`

The `skb` data type represents kernel `struct sk_buff` (socket buffer) object.
It extracts network packet information including source/destination addresses,
ports, and protocol.

In `matchArgs` or `matchData`, use network operators: `SAddr`, `DAddr`,
`SPort`, `DPort`, `Protocol`, or their negated variants. Address values
support CIDR notation.

## `sock`

The `sock` data type represents kernel `struct sock` object, which is the
network layer representation of a socket. It extracts socket family, type,
state, and address information.

In `matchArgs` or `matchData`, use network operators: `SAddr`, `DAddr`,
`SPort`, `DPort`, `Protocol`, `Family`, or `State`.

## `char_buf`

The `char_buf` data type represents a character buffer. When using this type,
specify the buffer size using `sizeArgIndex` (referencing another argument)
or `returnCopy` (using the return value).

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators.

## `char_iovec`

The `char_iovec` data type represents an I/O vector (`struct iovec`) for
scatter/gather I/O operations. Use `sizeArgIndex` to specify the vector count.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators.

## `filename`

The `filename` data type represents kernel `struct filename` object and
retrieves the user-provided filename string.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators
with path strings.

## `fd`

The `fd` data type represents a file descriptor. Tetragon resolves the
file descriptor to retrieve the associated file path.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators
with path strings.

## `cred`

The `cred` data type represents kernel `struct cred` object containing
process credentials including UIDs, GIDs, and capabilities.

## `const_buf`

The `const_buf` data type represents a buffer with a constant, statically
known size. Specify the buffer size using the `size` field.

## `nop`

The `nop` data type instructs Tetragon to skip retrieval of the argument.
No data is extracted for this argument position.

## `bpf_attr`

The `bpf_attr` data type represents the `union bpf_attr` structure used
in the `bpf()` syscall for BPF-related operations.

## `perf_event`

The `perf_event` data type represents kernel `struct perf_event` object
used for performance monitoring.

## `bpf_map`

The `bpf_map` data type represents kernel `struct bpf_map` object. It
extracts BPF map information including name, type, and key/value sizes.

## `bpf_prog`

The `bpf_prog` data type represents kernel `struct bpf_prog` object. It
extracts BPF program information including name and type.

## `user_namespace`

The `user_namespace` data type represents kernel `struct user_namespace`
object. It extracts the namespace identifier.

## `capability`

The `capability` data type represents a Linux capability value being
checked or modified.

## `kiocb`

The `kiocb` data type represents kernel `struct kiocb` (kernel I/O control
block) object. It retrieves the file path associated with the I/O operation.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators
with path strings.

See general path limitations in [path retrieval limits](#pathlimits).

## `iov_iter`

The `iov_iter` data type represents kernel `struct iov_iter` object, an
iterator for I/O operations over potentially multiple buffers.

## `load_info`

The `load_info` data type represents kernel `struct load_info` object
containing information about a kernel module being loaded.

## `module`

The `module` data type represents kernel `struct module` object. It extracts
kernel module information including its name.

## `syscall64`

The `syscall64` data type represents a syscall ID that distinguishes between
64-bit and 32-bit syscall ABIs. It outputs a `SyscallId` object containing
the syscall number and ABI (e.g., `x64`, `i386`). Commonly used with
`raw_syscalls` tracepoints and can be filtered with named syscalls using the
`InMap` operator.

## `kernel_cap_t`

The `kernel_cap_t` data type represents a kernel capability bitmask holding
the complete set of Linux capabilities.

## `cap_inheritable`

The `cap_inheritable` data type extracts the inheritable capability set
from a process's credentials (`struct cred`).

## `cap_permitted`

The `cap_permitted` data type extracts the permitted capability set
from a process's credentials (`struct cred`).

## `cap_effective`

The `cap_effective` data type extracts the effective capability set
from a process's credentials (`struct cred`).

## `linux_binprm`

The `linux_binprm` data type represents kernel `struct linux_binprm` object
and retrieves the `struct linux_binprm::file` full path.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators
with path strings.

See general path limitations in [path retrieval limits](#pathlimits).

## `data_loc`

The `data_loc` data type is used with tracepoints to extract dynamically
located string data using the kernel's `__data_loc` mechanism.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators.

## `net_device`

The `net_device` data type represents kernel `struct net_device` object.
It extracts the network device name (e.g., `eth0`, `lo`).

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators
with device name strings.

## `sockaddr`

The `sockaddr` data type represents kernel `struct sockaddr` object. It
extracts socket address information including family, IP address, port,
or Unix socket path.

In `matchArgs`, use `SAddr`, `SPort`, or `Family` operators. Note that
`sockaddr` does not support destination operators (`DAddr`, `DPort`).

## `socket`

The `socket` data type represents kernel `struct socket` object (BSD socket
layer), as opposed to `struct sock` (network layer).

In `matchArgs`, use network operators: `SAddr`, `DAddr`, `SPort`, `DPort`,
`Protocol`, `Family`, or `State`.

## `file`

The `file` data type represents kernel `struct file` object and retrieves
the file's full path.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators
with path strings.

See general path limitations in [path retrieval limits](#pathlimits).
Support for [file type filtering]({{< ref "selectors.md#file-type-filtering" >}}) is also available for this type.

## `dentry`

The `dentry` data type represents kernel `struct dentry` object retrieves
the related path within **one mountpoint**.

This stems from the fact that with just `struct dentry` tetragon does not have
mount information and does not have enough data to pass through main point within
the path.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators
with path strings.

See general path limitations in [path retrieval limits](#pathlimits).

## `path`

The `path` data type represents kernel `struct path` object retrieves
the related path.
Support for [file type filtering]({{< ref "selectors.md#file-type-filtering" >}}) is also available for this type.

In `matchArgs`, use `Equal`, `NotEqual`, `Prefix`, or `Postfix` operators
with path strings.

<a name="pathlimits"></a>

{{< caution >}}
Full path retrieval is available only on kernels `v5.3` and later.

On older kernels, there's a limit of 256 path components, which means
we can retrieve up to the maximum path length (4096 bytes), but only
with 256 path entries (directories and file name).
{{< /caution >}}
