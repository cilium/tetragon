# Java runtime class patching

Tetragon can redefine classes in an already-running HotSpot JVM with the
Linux Attach listener and a bundled native JVMTI helper. A policy carries the
replacement class files and the originals used for rollback. The target does
not need a JDK, compiler, Java agent JAR, or extra package installed.

The sensor scans `/proc` when the policy is enabled and once per second while
it remains enabled. `java.executables` is a list of exact absolute paths read
from `/proc/<pid>/exe`. Every `processArgsContains` token, when configured,
must occur in at least one NUL-separated command-line argument. Matching JVMs
are patched; later matching JVMs are picked up by the scanner.

A policy's `patches` entries pair a JVM class signature with complete
replacement and rollback `.class` files. The JVM checks the redefinition
constraints. In particular, standard HotSpot class redefinition does not allow
adding or removing fields or methods, changing method signatures, or changing
class hierarchy. The replacement and rollback files must preserve the loaded
class schema. A signature such as `Lcom/example/RequestHandler;` identifies the
class in the JVM. If multiple class loaders have loaded that class, each
matching class is redefined.

A matching JVM must permit Attach and native-agent loading, expose its mount
namespace under `/proc/<pid>/root`, and have the policy's classes loaded when
the patch is applied. `-XX:+DisableAttachMechanism` prevents this feature from
working. The sensor reports a policy-load error if an already-running matching
JVM cannot be patched; failures for JVMs discovered later are logged and
retried. Disabling or deleting the policy applies each rollback class file to
still-running targets. Exited processes need no rollback.

The native helper is compiled for the target architecture and shipped at
`/usr/lib/tetragon/tetragon-jvmti.so`. Build Tetragon with a JDK development
package available to the build environment; the installed target needs only
the Tetragon package and a compatible HotSpot JVM.

## Policy shape

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: java-runtime-patch
spec:
  java:
    executables:
      - /usr/lib/jvm/java-21-openjdk/bin/java
    processArgsContains:
      - com.example.Server
    patches:
      - signature: Lcom/example/RequestHandler;
        replacement: <base64-encoded replacement class file>
        rollback: <base64-encoded original class file>
```

Replace both class-file placeholders with base64-encoded complete `.class`
files. Each replacement must share the signature and schema of the loaded class;
its paired rollback file restores the original implementation.
