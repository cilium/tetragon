# Java JVMTI demo

On a Linux host with a working local Clang/LLVM BPF toolchain, a JDK, and the
kernel privileges required to run Tetragon, start the demo with:

```shell
sudo ./examples/java/run-demo.sh
```

The script builds Tetragon, its BPF programs, and the native JVMTI agent. It
installs the agent at `/usr/lib/tetragon/tetragon-jvmti.so`, starts
`TetragonJavaDemo`, and launches Tetragon with
[`demo-tracingpolicy.yaml`](demo-tracingpolicy.yaml). Tetragon prints events
for calls to `TetragonJavaDemo.work`. The script enables dynamic agent loading
when the installed JDK supports the `-XX:+EnableDynamicAgentLoading` option.
Press Ctrl-C to stop the demo.

The policy selects the target JVM with
`spec.java.targets.processArgsContains`. It requires the token
`tetragon-java-demo` to occur in one of that JVM's command-line arguments; the
script passes that token to the sample application. To monitor another JVM,
replace the token with a distinctive argument passed to that JVM. You can also
set `targets.executables` to the JVM executable's absolute path as it appears
in `/proc/<pid>/exe`.

The demo expects the target JVM to share the host mount namespace so it can
reach the configured Unix socket. The JVMTI helper is glibc-linked, so use a
glibc-based JVM for this demo.
