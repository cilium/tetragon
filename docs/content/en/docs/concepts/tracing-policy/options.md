---
title: "Options"
weight: 3
description: "Pass options to hook"
---

It's possible to pass options through spec file as an array of name and value pairs:

```yaml
spec:
  options:
    - name: "option-1"
      value: "True"
    - name: "option-2"
      value: "10"
```

Options array is passed and processed by each hook used in the spec file that
supports options. At the moment it's availabe for kprobe and uprobe hooks.

- [`Kprobe Options`](#kprobe-options): options for kprobe hooks.
- [`Uprobe Options`](#uprobe-options): options for uprobe hooks.

## Kprobe options

- [`disable-kprobe-multi`](#disable-kprobe-multi): disable kprobe multi link

### disable-kprobe-multi

This option disables kprobe multi link interface for all the kprobes defined in
the spec file. If enabled, all the defined kprobes will be atached through standard
kprobe interface. It stays enabled for another spec file without this option.

It takes boolean as value, by default it's false.

Example:

```yaml
  options:
    - name: "disable-kprobe-multi"
      value: "1"
```

## Uprobe options

- [`disable-uprobe-multi`](#disable-uprobe-multi): disable uprobe multi link

### disable-uprobe-multi

This option disables uprobe multi link interface for all the uprobes defined in
the spec file. If enabled, all the defined uprobes will be atached through standard
uprobe interface. It stays enabled for another spec file without this option.

It takes boolean as value, by default it's false.

Example:

```yaml
  options:
    - name: "disable-uprobe-multi"
      value: "1"
```
