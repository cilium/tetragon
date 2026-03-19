---
name: Release a new version of tetragon-rthooks
about: Create a checklist for an upcoming release
title: 'vX.Y.Z rthooks release'
labels: kind/release
assignees: ''
---

## Tetragon rthooks release checklist

 - [ ] Determine the next version. If backwords compability (with old Tetragon agents) is maintained just increase the patch
   version, otherwise increase the minor version. Note: The first time this happens, we will move
   from `v0.x` to `v1.0.0`.

- [ ] Tag with the next version:

      VERSION=v0.9
      git tag -a rthooks/$VERSION -m "rthooks: $VERSION release" -s
      git push origin rthooks/$VERSION
