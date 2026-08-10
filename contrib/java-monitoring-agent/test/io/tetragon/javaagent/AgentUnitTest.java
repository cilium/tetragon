/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

package io.tetragon.javaagent;

import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public final class AgentUnitTest {
	private static byte[] targetBytes() throws Exception {
		try (InputStream input = AgentUnitTest.class.getClassLoader()
				.getResourceAsStream("sample/TargetMethods.class")) {
			return input.readAllBytes();
		}
	}

	private static Set<String> instrumentedMethods(byte[] bytes) {
		Set<String> found = new HashSet<>();
		new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
			@Override
			public MethodVisitor visitMethod(int access, String name, String descriptor,
					String signature, String[] exceptions) {
				return new MethodVisitor(Opcodes.ASM9) {
					@Override
					public void visitMethodInsn(int opcode, String owner, String calledName,
							String calledDescriptor, boolean isInterface) {
						if (opcode == Opcodes.INVOKESTATIC
								&& owner.equals("io/tetragon/javaagent/TetragonAgent")
								&& calledName.equals("onMethodEntry")) {
							found.add(name + descriptor);
						}
					}
				};
			}
		}, 0);
		return found;
	}

	public static void main(String[] args) throws Exception {
		String className = "sample/TargetMethods";
		byte[] original = targetBytes();
		byte[] methods = new TetragonAgent.Transformer(className, "work")
				.transform(null, className, null, null, original);
		Set<String> found = instrumentedMethods(methods);
		Set<String> expected = Set.of("work()V", "work(I)V", "work(Ljava/lang/String;)V");
		if (!found.equals(expected)) {
			throw new AssertionError("instrumented methods " + found + ", expected " + expected);
		}

		byte[] constructors = new TetragonAgent.Transformer(className, "<init>")
				.transform(null, className, null, null, original);
		if (!instrumentedMethods(constructors).equals(Set.of("<init>()V"))) {
			throw new AssertionError("constructor was not instrumented safely");
		}

		byte[] allMethods = new TetragonAgent.Transformer(className, "")
				.transform(null, className, null, null, original);
		Set<String> expectedAll = Set.of("<init>()V", "work()V", "work(I)V",
				"work(Ljava/lang/String;)V", "untouched()V");
		if (!instrumentedMethods(allMethods).equals(expectedAll)) {
			throw new AssertionError("empty method filter did not instrument every method");
		}

		byte[] allClasses = new TetragonAgent.Transformer("", "work")
				.transform(null, className, null, null, original);
		if (!instrumentedMethods(allClasses).equals(expected)) {
			throw new AssertionError("empty class filter did not match the target class");
		}

		byte[] everything = new TetragonAgent.Transformer("", "")
				.transform(null, className, null, null, original);
		if (!instrumentedMethods(everything).equals(expectedAll)) {
			throw new AssertionError("empty filters did not instrument every method");
		}

		long id = TetragonAgent.methodId("example/Foo", "work", "(I)V");
		if (id != 0xf296cbc2a8e1eeebL) {
			throw new AssertionError("unexpected method ID: " + Long.toUnsignedString(id));
		}
	}
}
