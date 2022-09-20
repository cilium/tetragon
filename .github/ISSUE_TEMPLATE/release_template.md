---
name: Release a new version of Tetragon
about: Create a checklist for an upcoming release
title: 'vX.Y.Z release'
labels: kind/release
assignees: ''
---

## Tetragon release checklist

- [ ] Check that there are no [release blockers].
- [ ] Set `RELEASE` environment variable. For example, if you are releasing `v0.8.1`:
      ```
      export RELEASE=v0.8.1
      ```
- [ ] Open a pull request to update the Helm chart version:
      ```
      git checkout -b pr/prepare-$RELEASE
      ./contrib/update-helm-chart.sh $RELEASE
      git add install/kubernetes/
      git commit -s -m "Prepare for $RELEASE release"
      git push origin HEAD
      ```
- [ ] Once the pull request gets merged, create a tag for the release:
      ```
      git checkout main
      git pull origin main
      git tag -a $RELEASE -m "$RELEASE release" -s
      git push origin $RELEASE
      ```
- [ ] Go to [Image CI Releases workflow] and wait for the release image build to finish.
      - https://quay.io/repository/cilium/tetragon?tab=tags
      - https://quay.io/repository/cilium/tetragon-operator?tab=tags
- [ ] Publish Helm chart
      - Follow [cilium/charts RELEASE.md] to publish the Helm chart.
      - Once the chart is published, go to [cilium/charts GKE workflow] and wait for the
        CI run to pass.

[release blockers]: https://github.com/cilium/tetragon/issues?q=is%3Aissue+is%3Aopen+label%3Arelease-blocker
[Image CI Releases workflow]: https://github.com/cilium/tetragon/actions/workflows/build-images-releases.yml
[cilium/charts RELEASE.md]: https://github.com/cilium/charts/blob/master/RELEASE.md
[cilium/charts GKE workflow]: https://github.com/cilium/charts/actions/workflows/conformance-tetragon-gke.yaml
