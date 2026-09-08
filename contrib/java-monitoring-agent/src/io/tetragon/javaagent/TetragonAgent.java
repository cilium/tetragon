/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

package io.tetragon.javaagent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.AdviceAdapter;

/** Instruments entry into Java methods selected by optional class and method filters. */
public final class TetragonAgent {
	private static volatile UserRingBuffer ringBuffer;

	private TetragonAgent() {}

	public static void premain(String agentArgs, Instrumentation instrumentation) {
		Map<String, String> args = parseArgs(agentArgs);
		String className = argument(args, "class").replace('.', '/');
		String methodName = argument(args, "method");

		try {
			ringBuffer = UserRingBuffer.open();
		} catch (Exception e) {
			throw new IllegalStateException("failed to open Tetragon Java ring buffer", e);
		}

		instrumentation.addTransformer(new Transformer(className, methodName), false);
		System.err.printf("tetragon-java-agent: monitoring %s#%s via %s%n",
				wildcard(className), wildcard(methodName), UserRingBuffer.PIN_PATH);
	}

	private static String argument(Map<String, String> args, String key) {
		String value = args.get(key);
		if (value == null) {
			throw new IllegalArgumentException("-javaagent arguments must include class=<name>,method=<name>");
		}
		return value;
	}

	private static String wildcard(String value) {
		return value.isEmpty() ? "*" : value;
	}

	private static Map<String, String> parseArgs(String input) {
		Map<String, String> result = new HashMap<>();
		if (input != null) {
			for (String item : input.split(",")) {
				String[] pair = item.split("=", 2);
				if (pair.length == 2) {
					result.put(pair[0].trim(), pair[1].trim());
				}
			}
		}
		return result;
	}

	/** Entry point invoked by woven bytecode. */
	public static void onMethodEntry(long methodId, String className, String methodName, String descriptor) {
		UserRingBuffer rb = ringBuffer;
		if (rb != null) {
			rb.submit(methodId, className, methodName, descriptor);
		}
	}

	static long methodId(String className, String methodName, String descriptor) {
		long hash = 0xcbf29ce484222325L;
		for (String value : new String[] { className, methodName, descriptor }) {
			for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
				hash ^= b & 0xffL;
				hash *= 0x100000001b3L;
			}
			hash ^= 0;
			hash *= 0x100000001b3L;
		}
		return hash;
	}

	static final class Transformer implements ClassFileTransformer {
		private final String targetClass;
		private final String targetMethod;

		Transformer(String targetClass, String targetMethod) {
			this.targetClass = targetClass;
			this.targetMethod = targetMethod;
		}

		@Override
		public byte[] transform(ClassLoader loader, String className, Class<?> redefining,
				ProtectionDomain domain, byte[] bytes) {
			if ((!targetClass.isEmpty() && !targetClass.equals(className)) || excluded(className)) {
				return null;
			}
			try {
				ClassReader reader = new ClassReader(bytes);
				ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
				reader.accept(new Visitor(writer, className, targetMethod), ClassReader.EXPAND_FRAMES);
				return writer.toByteArray();
			} catch (Throwable error) {
				System.err.printf("tetragon-java-agent: failed to instrument %s: %s%n", className, error);
				return null;
			}
		}

		private static boolean excluded(String className) {
			return className.startsWith("java/") || className.startsWith("jdk/")
					|| className.startsWith("sun/") || className.startsWith("org/objectweb/asm/")
					|| className.startsWith("io/tetragon/javaagent/");
		}
	}

	private static final class Visitor extends ClassVisitor {
		private final String className;
		private final String targetMethod;

		Visitor(ClassVisitor visitor, String className, String targetMethod) {
			super(Opcodes.ASM9, visitor);
			this.className = className;
			this.targetMethod = targetMethod;
		}

		@Override
		public MethodVisitor visitMethod(int access, String name, String descriptor,
				String signature, String[] exceptions) {
			MethodVisitor visitor = super.visitMethod(access, name, descriptor, signature, exceptions);
			if (visitor == null || (!targetMethod.isEmpty() && !targetMethod.equals(name))
					|| "<clinit>".equals(name)) {
				return visitor;
			}
			long id = methodId(className, name, descriptor);
			return new AdviceAdapter(Opcodes.ASM9, visitor, access, name, descriptor) {
				@Override
				protected void onMethodEnter() {
					visitLdcInsn(id);
					visitLdcInsn(className);
					visitLdcInsn(name);
					visitLdcInsn(descriptor);
					visitMethodInsn(INVOKESTATIC, "io/tetragon/javaagent/TetragonAgent",
							"onMethodEntry", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", false);
				}
			};
		}
	}
}
