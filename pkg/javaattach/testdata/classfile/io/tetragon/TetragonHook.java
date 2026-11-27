// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package io.tetragon;

import java.util.ArrayList;
import java.util.List;

/**
 * Stand-in for the hook class of the tetragon jvmti agent, it records the
 * keys the rewritten classes call it with.
 */
public final class TetragonHook {
    public static final List<Long> keys = new ArrayList<>();

    private TetragonHook() {}

    public static void enter(long key) {
        keys.add(key);
    }
}
