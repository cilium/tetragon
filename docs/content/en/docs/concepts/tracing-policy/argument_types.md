---
title: "Argument types"
weight: 2
description: "Argument types for data retrieval"
---

Each argument definition specifies data type to be retrieved from kernel
argument. The list contains simple POD types or complex kernel objects
that are represented by extracted data type.

List of described data types:
- [`int, sint32, int32`](#int)
- [`uint32`]($uint32)
- [`long, sint64, int64`](#long)
- [`ulong, uint64`](#ulong)
- [`string`](#string):
- [`skb`](#skb):
- [`sock`](#sock):
- [`size_t`](#size_t):
- [`char_buf`](#char_buf):
- [`char_iovec`](#char_iovec):
- [`filename`](#filename):
- [`path`](#path):
- [`fd`](#fd):
- [`cred`](#cred):
- [`const_buf`](#const_buf):
- [`nop`](#nop):
- [`bpf_attr`](#bpf_attr):
- [`perf_event`](#perf_event):
- [`bpf_map`](#bpf_map):
- [`user_namespace`](#user_namespace):
- [`capability`](#capability):
- [`kiocb`](#kiocb):
- [`iov_iter`](#iov_iter):
- [`load_info`](#load_info):
- [`module`](#module):
- [`syscall64`](#syscall64):
- [`sint16`](#sint16):
- [`int16`](#int16):
- [`uint16`](#uint16):
- [`sint8`](#sint8):
- [`int8`](#int8):
- [`uint8`](#uint8):
- [`kernel_cap_t`](#kernel_cap_t):
- [`cap_inheritable`](#cap_inheritable):
- [`cap_permitted`](#cap_permitted):
- [`cap_effective`](#cap_effective):
- [`linux_binprm`](#linux_binprm):
- [`data_loc`](#data_loc):
- [`net_device`](#net_device):
- [`sockaddr`](#sockaddr):
- [`socket`](#socket):
- [`file`](#file): path from file object
- [`dentry`](#dentry): path from dentry object


<a name="int"></a>

## `int, sint32, int32`

The data type extracts 32-bit signed value.

## `uint32`

The data type extracts 32-bit unsigned value.

<a name="long"></a>

## `long, sint64, int64`

The data type extracts 64-bit signed value.

<a name="ulong"></a>

## `ulong, uint64`

The data type extracts  64-bit unsigned value.

## `string`

The data type extracts string terminated with zero byte.

## `skb`

## `sock`

## `size_t`

## `char_buf`

## `char_iovec`

## `filename`

## `path`

## `fd`

## `cred`

## `const_buf`

## `nop`

## `bpf_attr`

## `perf_event`

## `bpf_map`

## `user_namespace`

## `capability`

## `kiocb`

## `iov_iter`

## `load_info`

## `module`

## `syscall64`

## `sint16`

## `int16`

## `uint16`

## `sint8`

## `int8`

## `uint8`

## `kernel_cap_t`

## `cap_inheritable`

## `cap_permitted`

## `cap_effective`

## `linux_binprm`

## `data_loc`

## `net_device`

## `sockaddr`

## `socket`


## `file`

The `file` data type represents kernel `struct file` object and when used
it retrieves the file's full path.

The example shows `file_open` lsm hook:
```
LSM_HOOK_INIT(file_open, selinux_file_open),
static int selinux_file_open(struct file *file)
```

And related spec config that returns file path from the first argument:
```yaml
spec:
  lsmhooks:
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
```

## `dentry`

The `dentry` data type represents kernel `struct dentry` object and when used
it retrieves the file's path within **one mountpoint**.

This **limitation** stems from the fact that with just `struct dentry` tetragon
does not have mount information and does not have enough data to pass through
main point within the path.

The example shows `security_inode_follow_link` kprobe hook:

```
int security_inode_follow_link(struct dentry *dentry, struct inode *inode, bool rcu);
```

And related spec config that that retrieves path from the first argument:
```yaml
spec:
  kprobes:
  - call: "security_inode_follow_link"
    syscall: false
    args:
    - index: 0
      type: "dentry"
```
