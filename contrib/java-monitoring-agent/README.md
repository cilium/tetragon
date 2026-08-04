# Tetragon Java method monitoring agent

This JDK 22+ `-javaagent` instruments entry into selected Java methods and
submits fixed-size records directly to Tetragon's pinned
`BPF_MAP_TYPE_USER_RINGBUF`. The producer performs no syscall per event; the
always-loaded Tetragon BPF timer drains the map every millisecond.

## Build

Provide ASM and ASM Commons 9.x jars and a JDK 22 or newer:

```shell
make JAVA_HOME=/path/to/jdk-22 \
  ASM_JAR=/path/to/asm-9.7.jar \
  ASM_COMMONS_JAR=/path/to/asm-commons-9.7.jar
make JAVA_HOME=/path/to/jdk-22 sample
make JAVA_HOME=/path/to/jdk-22 ASM_JAR=/path/to/asm-9.7.jar \
  ASM_COMMONS_JAR=/path/to/asm-commons-9.7.jar test
```

## Run

For a local checkout, the helper scripts build and run the complete prototype.
The first script uses `JAVA_HOME` when it points to JDK 22+, otherwise it falls
back to the `eclipse-temurin:22-jdk` Docker image. It downloads the pinned ASM
9.7 dependencies into the ignored `build/deps` directory, builds Tetragon, BPF,
the CLI, agent, and sample, then starts Tetragon:

```shell
./run-tetragon.sh
```

Keep it running and launch the sample from another terminal:

```shell
./run-sample.sh
```

Use `JAVA_MONITOR_CLASS` and `JAVA_MONITOR_METHOD` to override the instrumented
class and method. Any command-line arguments to `run-tetragon.sh` are appended
to the Tetragon invocation, and arguments to `run-sample.sh` are passed to the
sample application.

Set either filter explicitly to an empty value to match everything. For
example, monitor all methods in all non-excluded classes with:

```shell
JAVA_MONITOR_CLASS= JAVA_MONITOR_METHOD= ./run-sample.sh
```

To watch only Java events from a third terminal:

```shell
../../tetra --server-address localhost:54321 getevents \
  --event-types PROCESS_JAVA -o compact
```

### Manual run

Start Tetragon first and verify that the producer map exists:

```shell
test -e /sys/fs/bpf/tetragon/tg_java_urb
```

Run the sample with the two ASM jars on the application class path. Class names
may use dots or JVM internal slashes. The `class` and `method` arguments are
required but may have empty values to act as wildcards; all matching overloads
are instrumented.
Use `method=<init>` to monitor constructor entry; ASM Commons inserts the call
after the required `this()` or `super()` constructor invocation.

Use `class=,method=` to monitor all methods in all non-excluded classes. Java
runtime, ASM, and agent implementation classes remain excluded; class
initializers (`<clinit>`) are not instrumented. Monitoring everything can
generate a very high event rate.

```shell
/path/to/jdk-22/bin/java --enable-native-access=ALL-UNNAMED \
  -javaagent:./tetragon-java-monitoring-agent.jar=class=sample.Sample,method=work \
  -cp build/sample:/path/to/asm-9.7.jar:/path/to/asm-commons-9.7.jar \
  sample.Sample
```

Tetragon exports `process_java` events containing the JVM process, parent and
configured ancestors, cached Linux TID, stable method ID, internal class name,
method name, and JVM descriptor. The method ID is 64-bit FNV-1a over the three
UTF-8 strings separated by NUL bytes. Strings are truncated to 127 bytes and
NUL-padded in their 128-byte wire fields.

The prototype has fixed settings: `/sys/fs/bpf/tetragon/tg_java_urb`, 64 KiB
map size, and a 1 ms timer. One JVM producer per map is supported. The JVM must
see the host bpffs mount and have permission to obtain and mmap the map.
