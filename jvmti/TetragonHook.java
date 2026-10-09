// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package io.tetragon;

/**
 * Hook called at the entry of java methods instrumented by the tetragon
 * jvmti agent. The class is defined by the agent in the bootstrap class
 * loader and the native method is implemented by the agent.
 */
public final class TetragonHook {
    private TetragonHook() {}

    public static native void enter(long key);
}
