# Java JVMTI demo

On a Linux host with a working local Clang/LLVM BPF toolchain, Go, a JDK and
`sudo` access, start the demo as a regular user with:

```shell
./examples/java/run-demo.sh
```

The script builds Tetragon, its BPF programs, `tetra` and the native JVMTI
agent, and starts `TetragonJavaDemo`, all as the invoking user. Only Tetragon
itself runs as root: the script starts it through `sudo` with
[`demo-tracingpolicy.yaml`](demo-tracingpolicy.yaml) and the agent library
from the build tree (`--java-agent-path`), so nothing is installed on the
system.

The script does not print the events itself. Once Tetragon is running, watch
the Java ones from another terminal with:

```shell
./tetra getevents -o compact --event-types PROCESS_JAVA
```

It prints one line for each call of `TetragonJavaDemo.work`. The Tetragon log
goes to a file in a temporary directory, its path is printed when Tetragon
starts. The script enables dynamic agent loading when the installed JDK
supports the `-XX:+EnableDynamicAgentLoading` option. Press Ctrl-C to stop the
demo.

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
