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
import java.nio.charset.StandardCharsets;

/** A non-blocking FFM producer for BPF_MAP_TYPE_USER_RINGBUF. */
final class UserRingBuffer implements AutoCloseable {
	static final String PIN_PATH = "/sys/fs/bpf/tetragon/tg_java_urb";
	static final long MAP_SIZE = 65_536;
	static final int STRING_LEN = 128;
	static final int RECORD_LEN = 432;

	private static final int MSG_OP_JAVA = 29;
	private static final int BPF_OBJ_GET = 7;
	private static final int PROT_READ = 1;
	private static final int PROT_WRITE = 2;
	private static final int MAP_SHARED = 1;
	private static final int BUSY_BIT = 1 << 31;
	private static final int HEADER_LEN = 8;
	private static final int SC_PAGESIZE = 30;

	private static final Linker LINKER = Linker.nativeLinker();
	private static final SymbolLookup LIBC = LINKER.defaultLookup();
	private static final MethodHandle SYSCALL = downcallVariadic("syscall", FunctionDescriptor.of(
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
			ValueLayout.ADDRESS, ValueLayout.JAVA_LONG), 1);
	private static final MethodHandle SYSCONF = downcall("sysconf", FunctionDescriptor.of(
			ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));
	private static final MethodHandle GETTID = downcall("gettid", FunctionDescriptor.of(ValueLayout.JAVA_INT));
	private static final MethodHandle MMAP = downcall("mmap", FunctionDescriptor.of(
			ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
			ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
	private static final MethodHandle MUNMAP = downcall("munmap", FunctionDescriptor.of(
			ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
	private static final MethodHandle CLOSE = downcall("close", FunctionDescriptor.of(
			ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

	private static final VarHandle LONG = ValueLayout.JAVA_LONG.varHandle();
	private static final VarHandle INT = ValueLayout.JAVA_INT.varHandle();
	private static final long JVM_PID = ProcessHandle.current().pid();
	private static final ThreadLocal<Integer> LINUX_TID = ThreadLocal.withInitial(UserRingBuffer::gettid);

	private final Arena arena;
	private final MemorySegment consumerPage;
	private final MemorySegment producerPage;
	private final long pageSize;
	private final Object writeLock = new Object();

	private UserRingBuffer(Arena arena, MemorySegment consumerPage,
			MemorySegment producerPage, long pageSize) {
		this.arena = arena;
		this.consumerPage = consumerPage;
		this.producerPage = producerPage;
		this.pageSize = pageSize;
	}

	private static MethodHandle downcall(String name, FunctionDescriptor descriptor) {
		MemorySegment symbol = LIBC.find(name)
				.orElseThrow(() -> new UnsatisfiedLinkError("libc symbol not found: " + name));
		return LINKER.downcallHandle(symbol, descriptor);
	}

	private static MethodHandle downcallVariadic(String name, FunctionDescriptor descriptor,
			int firstVariadicArgument) {
		MemorySegment symbol = LIBC.find(name)
				.orElseThrow(() -> new UnsatisfiedLinkError("libc symbol not found: " + name));
		return LINKER.downcallHandle(symbol, descriptor,
				Linker.Option.firstVariadicArg(firstVariadicArgument));
	}

	private static long sysBpfNumber() {
		return switch (System.getProperty("os.arch")) {
		case "amd64", "x86_64" -> 321L;
		case "aarch64" -> 280L;
		default -> throw new UnsupportedOperationException("unsupported Linux architecture: "
				+ System.getProperty("os.arch"));
		};
	}

	static UserRingBuffer open() throws IOException {
		Arena arena = Arena.ofShared();
		try {
			long pageSize;
			try {
				pageSize = (long) SYSCONF.invokeExact(SC_PAGESIZE);
			} catch (Throwable error) {
				throw new IOException("sysconf(_SC_PAGESIZE) failed", error);
			}
			if (pageSize <= 0 || MAP_SIZE % pageSize != 0) {
				throw new IOException("invalid host page size for Java ring buffer: " + pageSize);
			}

			MemorySegment path = cString(arena, PIN_PATH);
			MemorySegment attr = arena.allocate(16, 8);
			attr.set(ValueLayout.ADDRESS, 0, path);
			attr.set(ValueLayout.JAVA_INT, 8, 0);
			attr.set(ValueLayout.JAVA_INT, 12, 0);
			int fd;
			try {
				fd = (int) (long) SYSCALL.invokeExact(sysBpfNumber(), (long) BPF_OBJ_GET, attr, 16L);
			} catch (Throwable error) {
				throw new IOException("syscall(BPF_OBJ_GET) failed", error);
			}
			if (fd < 0) {
				throw new IOException("BPF_OBJ_GET failed for " + PIN_PATH);
			}

			long producerLength = pageSize + 2 * MAP_SIZE;
			try {
				MemorySegment consumerAddress = mmap(fd, pageSize, PROT_READ, 0);
				MemorySegment producerAddress = mmap(fd, producerLength,
						PROT_READ | PROT_WRITE, pageSize);
				MemorySegment consumer = consumerAddress.reinterpret(pageSize, arena,
						segment -> munmap(segment, pageSize));
				MemorySegment producer = producerAddress.reinterpret(producerLength, arena,
						segment -> munmap(segment, producerLength));
				return new UserRingBuffer(arena, consumer, producer, pageSize);
			} finally {
				close(fd);
			}
		} catch (IOException | RuntimeException error) {
			arena.close();
			throw error;
		}
	}

	private static MemorySegment cString(Arena arena, String value) {
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		MemorySegment segment = arena.allocate(bytes.length + 1);
		MemorySegment.copy(MemorySegment.ofArray(bytes), 0, segment, 0, bytes.length);
		segment.set(ValueLayout.JAVA_BYTE, bytes.length, (byte) 0);
		return segment;
	}

	private static MemorySegment mmap(int fd, long length, int protection, long offset) throws IOException {
		try {
			MemorySegment address = (MemorySegment) MMAP.invokeExact(MemorySegment.NULL,
					length, protection, MAP_SHARED, fd, offset);
			if (address.address() == -1L) {
				throw new IOException("mmap failed");
			}
			return address;
		} catch (IOException error) {
			throw error;
		} catch (Throwable error) {
			throw new IOException("mmap downcall failed", error);
		}
	}

	private static int gettid() {
		try {
			return (int) GETTID.invokeExact();
		} catch (Throwable error) {
			throw new IllegalStateException("gettid failed", error);
		}
	}

	private static void close(int fd) {
		try { int ignored = (int) CLOSE.invokeExact(fd); } catch (Throwable ignored) {}
	}

	private static void munmap(MemorySegment address, long length) {
		try { int ignored = (int) MUNMAP.invokeExact(address, length); } catch (Throwable ignored) {}
	}

	boolean submit(long methodId, String className, String methodName, String descriptor) {
		int tid = LINUX_TID.get();
		synchronized (writeLock) {
			long total = HEADER_LEN + RECORD_LEN;
			long producer = (long) LONG.get(producerPage, 0L);
			long consumer = (long) LONG.getAcquire(consumerPage, 0L);
			if (producer - consumer + total > MAP_SIZE) {
				return false;
			}

			long recordOffset = pageSize + (producer & (MAP_SIZE - 1));
			INT.setRelease(producerPage, recordOffset, RECORD_LEN | BUSY_BIT);
			INT.set(producerPage, recordOffset + 4, 0);
			long payload = recordOffset + HEADER_LEN;
			producerPage.asSlice(payload, RECORD_LEN).fill((byte) 0);

			producerPage.set(ValueLayout.JAVA_BYTE, payload, (byte) MSG_OP_JAVA);
			INT.set(producerPage, payload + 4, RECORD_LEN);
			LONG.set(producerPage, payload + 8, System.nanoTime());
			INT.set(producerPage, payload + 16, (int) JVM_PID);
			LONG.set(producerPage, payload + 32, methodId);
			INT.set(producerPage, payload + 40, tid);
			putString(producerPage, payload + 44, className);
			putString(producerPage, payload + 172, methodName);
			putString(producerPage, payload + 300, descriptor);

			INT.setRelease(producerPage, recordOffset, RECORD_LEN);
			LONG.setRelease(producerPage, 0L, producer + total);
			return true;
		}
	}

	private static void putString(MemorySegment destination, long offset, String value) {
		byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
		int length = Math.min(bytes.length, STRING_LEN - 1);
		MemorySegment.copy(MemorySegment.ofArray(bytes), 0, destination, offset, length);
	}

	@Override
	public void close() {
		arena.close();
	}
}
