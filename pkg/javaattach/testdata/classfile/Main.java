// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

import io.tetragon.TetragonHook;
import java.util.List;

/**
 * Runs the class file rewriter test cases and prints one line for each:
 * name, result and the keys that TetragonHook.enter was called with.
 * The class itself is not rewritten, see classfile_linux_test.go.
 */
public class Main {
    static void report(String name, Object result) {
        StringBuilder keys = new StringBuilder();

        for (long key : TetragonHook.keys) {
            if (keys.length() > 0)
                keys.append(',');
            keys.append(key);
        }
        System.out.println(name + "\t" + result + "\t" + keys);
        TetragonHook.keys.clear();
    }

    public static void main(String[] args) {
        // load the class, so its initializer does not run in the first case
        Cases.sink = 0;
        TetragonHook.keys.clear();

        report("staticAdd", Cases.staticAdd(2, 3));
        report("instanceMul", new Cases().instanceMul(2));
        report("constructor", Cases.constructor(7));
        report("defaultMethod", Cases.defaultMethod());
        report("denseSwitch", Cases.denseSwitch(0) + Cases.denseSwitch(3) + Cases.denseSwitch(9));
        report("sparseSwitch", Cases.sparseSwitch(100) + Cases.sparseSwitch(10000) + Cases.sparseSwitch(5));
        report("tryCatch", Cases.tryCatch("12") + Cases.tryCatch("x") + Cases.sink);
        report("loop", Cases.loop(10));
        report("loopAtStart", Cases.loopAtStart(10));
        report("uninitialized", Cases.uninitialized(true) + Cases.uninitialized(false));
        report("wide", Cases.wide(5000));
        report("lambda", Cases.lambda(4));
        report("stringSwitch", Cases.stringSwitch("a") + Cases.stringSwitch("bb") + Cases.stringSwitch("c"));
        report("record", Cases.record(3));
        report("patternSwitch", Cases.patternSwitch(9) + Cases.patternSwitch(1) + Cases.patternSwitch("s") +
                                Cases.patternSwitch(1.5));
        report("generics", Cases.generics(List.of("ab", "cde")));
        report("abstractMethod", Cases.abstractMethod());
        report("big", Big.big(1));
    }
}
