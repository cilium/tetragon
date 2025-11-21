# Who is using Tetragon?

As Tetragon continues to establish itself as the standard for security
observability and runtime enforcement in the cloud native ecosystem, sharing
experiences and learning from others becomes increasingly valuable the growth
of the project and community behind it.

We are often asked who is using specific features of Tetragon, or whether
certain platforms and products have it integrated it so that users can connect,
exchange ideas, and share best practices.

The following directory of adopters helps identify who is using Tetragon, how
they are using it, and where you can reach out to collaborate or learn more.
Each entry is maintained directly by the users themselves.

## Adding yourself as a user

If you are using Tetragon, or have integrated it into your product, platform,
or service, we would love for you to add yourself to the list.

Sharing your use case helps new adopters to explore what is possible with
Tetragon. You can do by opening a pull request to this file and adding a short
section describing your usage. If you're open to being contacted about your
experience, please include your Slack handle.

    N: Name of user (company)
    D: Description
    U: Usage of features
    L: Link with further information (optional)
    Q: Contacts available for questions (optional)

Example entry:

    * N: Tetragon Example User Inc.
      D: Tetragon Example User Inc. is using Tetragon for scientific purposes
      U: File access monitoring, Process monitoring, Network monitoring
      Q: @slacknick1, @slacknick2

## Requirements to be listed

* You must represent the user listed. Do *NOT* add entries on behalf of other
  users.
* There is no minimum deployment size but we request to list permanent
  production deployments only, i.e., no demo or trial deployments. Commercial
  use is not required.

## Users (Alphabetically)

    * N: FRSCA - Factory for Repeatable Secure Creation of Artifacts
      D: FRSCA is utilizing Tetragon integrated with Tekton to create runtime attestation to attest artifact and builder attributes
      U: Runtime security 
      L: https://github.com/buildsec/frsca
      Q: @Parth Patel

    * N: Incentive.me
      D: Incentive.me uses Tetragon for security of its environments
      U: Runtime security
      L: https://incentive.me
      Q: @lucasfcnunes

    * N: Intility AS
      D: Intility is a managed service provider for enterprises and we use Cilium, Tetragon, and Hubble to deliver world class managed Kubernetes clusters to customers from our own private cloud
      U: Runtime security
      L: https://intility.com/container-platform/
      Q: @jonasks, @daniwk, @stianfro

    * N: Parseable
      D: Parseable uses Tetragon for collecting and ingesting eBPF logs for Kubernetes clusters
      U: Runtime security
      L: https://www.parseable.io/blog/ebpf-log-analytics
      Q: @nitisht

    * N: Reddit
      D: Reddit uses Tetragon to identify security risks and policy violations
      U: Visibility into linux system calls, use of kernel modules, process events, file access behavior, and network behavior
      L: https://www.reddit.com/r/RedditEng/comments/1hv3sc7/tetragon_configuration_gotchas/

    * N: SINAD
      D: SINAD uses Cilium and integrates Tetragon into their application EzyKube 
      U: Runtime security
      L: https://sinad.io 

    * N: Stream Security
      D: Stream Security uses Tetragon for Network, Process, and File observability and protection in Kubernetes clusters
      U: Network monitoring, Process monitoring, File access monitoring
      L: https://www.stream.security/
      Q: @vitali-streamsec
