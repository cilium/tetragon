---
title: "Argument types"
weight: 2
description: "Argument types for data retrieval"
---

Each argument definition specifies data type to be retrieved from kernel
argument. The list contains simple POD types and several complex kernel
objects that are represented by extracted data type.

List of described data types:
- [`int8`](#int8)
- [`uint8`](#uint8)
- [`int16`](#int16)
- [`uint16`](#uint16)
- [`int, int32`](#int)
- [`uint32`](#uint32)
- [`int64`](#int64)
- [`ulong, size_t`](#uint64)
- [`string`](#string)
- [`skb`](#skb)
- [`sock`](#sock)
- [`char_buf`](#char_buf)
- [`char_iovec`](#char_iovec)
- [`filename`](#filename)
- [`path`](#path)
- [`fd`](#fd)
- [`cred`](#cred)
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

## `int8`

The data type extracts 8-bit signed value.

## `uint8`

The data type extracts 8-bit unsigned value.

## `int16`

The data type extracts 16-bit signed value.

## `uint16`

The data type extracts 16-bit unsigned value.

<a name="int"></a>

## `int, int32`

The data type extracts 32-bit signed value.

## `uint32`

The data type extracts 32-bit unsigned value.

## `int64`

The data type extracts 64-bit signed value.

<a name="uint64"></a>

## `uint64, size_t`

The data type extracts  64-bit unsigned value.

## `string`

The data type extracts string terminated with zero byte.

## `skb`

TBD

## `sock`

TBD

## `char_buf`

TBD

## `char_iovec`

TBD

## `filename`

TBD

## `fd`

TBD

## `cred`

TBD

## `nop`

TBD

## `bpf_attr`

TBD

## `perf_event`

TBD

## `bpf_map`

TBD

## `bpf_prog`

TBD

## `user_namespace`

TBD

## `capability`

TBD

## `kiocb`

TBD

## `iov_iter`

TBD

## `load_info`

TBD

## `module`

TBD

## `syscall64`

TBD

## `kernel_cap_t`

TBD

## `cap_inheritable`

TBD

## `cap_permitted`

TBD

## `cap_effective`

TBD

## `linux_binprm`

The `linux_binprm` data type represents kernel `struct linux_binprm` object
and retrieves the `struct linux_binprm::file` full path.

## `data_loc`

TBD

## `net_device`

TBD

## `sockaddr`

TBD

## `socket`

TBD

## `file`

The `file` data type represents kernel `struct file` object and retrieves
the file's full path.

## `dentry`

The `dentry` data type represents kernel `struct dentry` object retrieves
the related path within **one mountpoint**.

This stems from the fact that with just `struct dentry` tetragon does not have
mount information and does not have enough data to pass through main point within
the path.

## `path`

The `path` data type represents kernel `struct path` object retrieves
the related path.

{{< caution >}}
Full path retrieval is available only on kernels `v5.3` and later.

On older kernels, there's a limit of 256 path components, which means
we can retrieve up to the maximum path length (4096 bytes), but only
with 256 path entries (directories and file name).
{{< /caution >}}

