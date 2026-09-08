/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

package io.tetragon.javaagent;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Fixed-size, non-blocking SPSC producer into a shared-memory ring file that Tetragon creates.
 * There is no handshake: the ring's path, size, and layout are a fixed convention shared with
 * Tetragon, so this is meant for local/trusted use, not as a general IPC protocol.
 */
final class JavaIPC implements AutoCloseable {
  static final String DEFAULT_PATH = "/var/run/tetragon/java.ring";
  private static final int RECORD_LEN = 432;
  private static final int STRING_LEN = 128;
  private static final int RING_SIZE = 4 * 1024 * 1024;
  private static final int HEADER_LEN = 256;
  private static final int PRODUCER_OFF = 64;
  private static final int CONSUMER_OFF = 128;
  private static final int NOTIFY_OFF = 192;
  private static final int MAGIC = 0x4a52534a;
  private static final int VERSION = 1;
  private static final int O_RDWR = 2;
  private static final int PROT_READ = 1;
  private static final int PROT_WRITE = 2;
  private static final int MAP_SHARED = 1;
  private static final int FUTEX_WAKE = 1;
  private static final int MSG_OP_JAVA = 29;

  private static final Linker LINKER = Linker.nativeLinker();
  private static final SymbolLookup LIBC = LINKER.defaultLookup();
  private static final MethodHandle OPEN =
      downcall(
          "open",
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
  private static final MethodHandle MMAP =
      downcall(
          "mmap",
          FunctionDescriptor.of(
              ValueLayout.ADDRESS,
              ValueLayout.ADDRESS,
              ValueLayout.JAVA_LONG,
              ValueLayout.JAVA_INT,
              ValueLayout.JAVA_INT,
              ValueLayout.JAVA_INT,
              ValueLayout.JAVA_LONG));
  private static final MethodHandle MUNMAP =
      downcall(
          "munmap",
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
  private static final MethodHandle SYSCALL =
      downcall(
          "syscall",
          FunctionDescriptor.of(
              ValueLayout.JAVA_LONG,
              ValueLayout.JAVA_LONG,
              ValueLayout.ADDRESS,
              ValueLayout.JAVA_LONG,
              ValueLayout.JAVA_LONG,
              ValueLayout.ADDRESS,
              ValueLayout.ADDRESS));
  private static final MethodHandle CLOSE =
      downcall("close", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
  private static final MethodHandle GETTID =
      downcall("gettid", FunctionDescriptor.of(ValueLayout.JAVA_INT));

  private static final VarHandle INT =
      ValueLayout.JAVA_INT.withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();
  private static final VarHandle LONG =
      ValueLayout.JAVA_LONG.withOrder(ByteOrder.LITTLE_ENDIAN).varHandle();
  private static final long JVM_PID = ProcessHandle.current().pid();
  private static final int SYS_FUTEX = futexNumber();
  private static final ThreadLocal<Integer> LINUX_TID = ThreadLocal.withInitial(JavaIPC::gettid);

  private final Arena arena;
  private final int ringFd;
  private final MemorySegment ring;
  private final MemorySegment packet;
  private final long mappedLength;
  private final long slots;
  private final long mask;
  private final Object writeLock = new Object();
  private boolean closed;

  private JavaIPC(Arena arena, int ringFd, MemorySegment ring, long mappedLength, long slots) {
    this.arena = arena;
    this.ringFd = ringFd;
    this.ring = ring;
    this.packet = arena.allocate(RECORD_LEN, 8);
    this.mappedLength = mappedLength;
    this.slots = slots;
    this.mask = slots - 1;
  }

  private static MethodHandle downcall(String name, FunctionDescriptor descriptor) {
    MemorySegment symbol =
        LIBC.find(name)
            .orElseThrow(() -> new UnsatisfiedLinkError("libc symbol not found: " + name));
    return LINKER.downcallHandle(symbol, descriptor);
  }

  /**
   * Opens the ring file Tetragon already created at path. The ring's slot count and mapped length
   * are computed independently here from the same RECORD_LEN/RING_SIZE/HEADER_LEN constants
   * Tetragon uses, so both sides agree on the layout without negotiating it; the header is then
   * validated as a sanity check.
   */
  static JavaIPC open(String path) throws IOException {
    Arena arena = Arena.ofShared();
    int ringFd = -1;
    MemorySegment ring = null;
    long mappedLength = 0;
    try {
      long slots = 1;
      while (HEADER_LEN + (slots << 1) * RECORD_LEN <= RING_SIZE) {
        slots <<= 1;
      }
      slots >>= 1;
      mappedLength = HEADER_LEN + slots * RECORD_LEN;

      MemorySegment cRingPath = cString(arena, path);
      ringFd = (int) OPEN.invokeExact(cRingPath, O_RDWR);
      if (ringFd < 0) {
        throw new IOException("open shared-memory ring failed: " + path);
      }
      MemorySegment mapped =
          (MemorySegment)
              MMAP.invokeExact(
                  MemorySegment.NULL, mappedLength, PROT_READ | PROT_WRITE, MAP_SHARED, ringFd, 0L);
      if (mapped.address() == -1L) {
        throw new IOException("mmap shared-memory ring failed");
      }
      ring = mapped.reinterpret(mappedLength);
      if ((int) INT.get(ring, 0L) != MAGIC
          || (int) INT.get(ring, 4L) != VERSION
          || (int) INT.get(ring, 8L) != RECORD_LEN
          || (long) LONG.get(ring, 16L) != slots) {
        throw new IOException("unexpected Java ring header in " + path);
      }
      return new JavaIPC(arena, ringFd, ring, mappedLength, slots);
    } catch (IOException | RuntimeException error) {
      cleanup(ringFd, ring, mappedLength, arena);
      throw error;
    } catch (Throwable error) {
      cleanup(ringFd, ring, mappedLength, arena);
      throw new IOException("opening Java shared-memory IPC failed", error);
    }
  }

  boolean submit(long methodId, String className, String methodName, String descriptor) {
    synchronized (writeLock) {
      if (closed) {
        return false;
      }
      long producer = (long) LONG.getAcquire(ring, PRODUCER_OFF);
      long consumer = (long) LONG.getAcquire(ring, CONSUMER_OFF);
      if (producer - consumer >= slots) {
        return false;
      }
      packet.fill((byte) 0);
      packet.set(ValueLayout.JAVA_BYTE, 0, (byte) MSG_OP_JAVA);
      INT.set(packet, 4L, RECORD_LEN);
      LONG.set(packet, 8L, System.nanoTime());
      INT.set(packet, 16L, (int) JVM_PID);
      LONG.set(packet, 32L, methodId);
      INT.set(packet, 40L, LINUX_TID.get());
      putString(44, className);
      putString(172, methodName);
      putString(300, descriptor);
      long offset = HEADER_LEN + (producer & mask) * RECORD_LEN;
      MemorySegment.copy(packet, 0, ring, offset, RECORD_LEN);
      LONG.setRelease(ring, PRODUCER_OFF, producer + 1);
      if (producer == consumer) {
        INT.getAndAdd(ring, NOTIFY_OFF, 1);
        try {
          SYSCALL.invokeExact(
              (long) SYS_FUTEX,
              ring.asSlice(NOTIFY_OFF, 4L),
              (long) FUTEX_WAKE,
              1L,
              MemorySegment.NULL,
              MemorySegment.NULL);
        } catch (Throwable ignored) {
          // Best-effort wake; the consumer will still find the record on its next poll.
        }
      }
      return true;
    }
  }

  private void putString(long offset, String value) {
    byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    int length = Math.min(bytes.length, STRING_LEN - 1);
    while (length > 0 && !validUtf8(bytes, length)) {
      length--;
    }
    MemorySegment.copy(MemorySegment.ofArray(bytes), 0, packet, offset, length);
  }

  private static boolean validUtf8(byte[] bytes, int length) {
    try {
      StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes, 0, length));
      return true;
    } catch (CharacterCodingException error) {
      return false;
    }
  }

  private static MemorySegment cString(Arena arena, String value) {
    byte[] bytes = (value + "\0").getBytes(StandardCharsets.UTF_8);
    MemorySegment result = arena.allocate(bytes.length, 1);
    MemorySegment.copy(MemorySegment.ofArray(bytes), 0, result, 0, bytes.length);
    return result;
  }

  private static int futexNumber() {
    return switch (System.getProperty("os.arch")) {
      case "aarch64", "riscv64" -> 98;
      case "ppc64le" -> 221;
      default -> 202;
    };
  }

  private static int gettid() {
    try {
      return (int) GETTID.invokeExact();
    } catch (Throwable error) {
      throw new IllegalStateException("gettid failed", error);
    }
  }

  private static void closeFd(int fd) {
    if (fd >= 0) {
      try {
        CLOSE.invokeExact(fd);
      } catch (Throwable ignored) {
        // Best-effort close.
      }
    }
  }

  private static void cleanup(int ringFd, MemorySegment ring, long length, Arena arena) {
    if (ring != null && length != 0) {
      try {
        MUNMAP.invokeExact(ring, length);
      } catch (Throwable ignored) {
        // Best-effort unmap.
      }
    }
    closeFd(ringFd);
    arena.close();
  }

  @Override
  public void close() {
    synchronized (writeLock) {
      if (closed) {
        return;
      }
      closed = true;
    }
    cleanup(ringFd, ring, mappedLength, arena);
  }
}
