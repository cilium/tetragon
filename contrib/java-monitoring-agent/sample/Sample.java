/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

package sample;

public final class Sample {
	public Sample() {
		work("constructor");
	}

	public static void work(String value) {
		System.out.println(value);
	}

	public static int work(int value) {
		return value + 1;
	}

	public static void main(String[] args) throws Exception {
		new Sample();
		while (true) {
			work("tick");
			work(42);
			Thread.sleep(1000);
		}
	}
}
