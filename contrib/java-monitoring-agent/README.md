# Tetragon Java method monitoring agent

This JDK 22+ `-javaagent` instruments selected method entries and publishes
fixed 432-byte records into a shared-memory ring file that Tetragon creates
at `/var/run/tetragon/java.ring`. There is no handshake: the agent just opens
that existing file, so Tetragon must already be running with Java IPC
enabled; submission is non-blocking and drops when the ring is full. Only
one JVM can attach at a time, and the record's PID is self-reported by the
JVM rather than authenticated — this is meant for local/trusted use.
Tetragon typically runs as root while the JVM doesn't, so the ring file is
created world-readable/writable (0666) rather than restricted to a group the
JVM's user may not belong to; any local user can read or write it.

Build with ASM 9.x and a JDK 22 or newer:

```shell
make JAVA_HOME=/path/to/jdk-22 \
  ASM_JAR=/path/to/asm-9.x.jar \
  ASM_COMMONS_JAR=/path/to/asm-commons-9.x.jar
```

Start Tetragon with Java IPC enabled (`--java-ipc-path`), then run an
application with native access enabled:

```shell
/path/to/jdk-22/bin/java --enable-native-access=ALL-UNNAMED \
  -javaagent:./tetragon-java-monitoring-agent.jar=class=sample.Sample,method=work \
  -cp build/sample:/path/to/asm-9.x.jar:/path/to/asm-commons-9.x.jar \
  sample.Sample
```

The `class` and `method` arguments are required and may be empty to match all
non-excluded classes or methods. Overloads include their JVM descriptor. An
optional `path=<ring file>` argument overrides the default
`/var/run/tetragon/java.ring`. Records contain the Java submission timestamp,
stable FNV-1a method ID, class, method, descriptor, self-reported JVM PID,
and Linux TID.
