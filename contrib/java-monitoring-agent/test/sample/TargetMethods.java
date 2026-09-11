/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

package sample;

final class TargetMethods {
	TargetMethods() {}
	void work() {}
	void work(int value) {}
	static void work(String value) {}
	void untouched() {}
}
