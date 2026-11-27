// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.ArrayList;
import java.util.List;
import java.util.function.IntUnaryOperator;

/**
 * Methods for the class file rewriter test, each of them has the bytecode
 * or the Code attributes that some part of the rewriter needs to handle.
 * The methods are called from Main, see classfile_linux_test.go.
 */
public class Cases {
    static int sink;

    // class initializer is not instrumented
    static {
        sink = 1;
    }

    static int staticAdd(int a, int b) {
        return a + b;
    }

    int instanceMul(int a) {
        return a * 3;
    }

    static class Box {
        final int v;

        Box(int v) {
            this.v = v;
        }

        int get() {
            return v;
        }
    }

    static int constructor(int x) {
        return new Box(x).get();
    }

    interface Greeter {
        default String greet(String s) {
            return "hi " + s;
        }
    }

    static String defaultMethod() {
        return new Greeter() {}.greet("x");
    }

    // tableswitch
    static int denseSwitch(int x) {
        switch (x) {
        case 0:
            return 10;
        case 1:
            return 11;
        case 2:
            return 12;
        case 3:
            return 13;
        default:
            return -1;
        }
    }

    // lookupswitch
    static int sparseSwitch(int x) {
        switch (x) {
        case 1:
            return 1;
        case 100:
            return 2;
        case 10000:
            return 3;
        default:
            return -1;
        }
    }

    // exception table
    static int tryCatch(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        } finally {
            sink++;
        }
    }

    static int loop(int n) {
        int s = 0;

        for (int i = 0; i < n; i++)
            s += i;
        return s;
    }

    // the loop jumps back to the first instruction of the method
    static int loopAtStart(int n) {
        do {
            n -= 3;
        } while (n > 0);
        return n;
    }

    // branch between new and the constructor call, the stack map frame
    // has uninitialized object in it
    static String uninitialized(boolean c) {
        return new String(c ? "a" : "b");
    }

    // wide iinc
    static int wide(int x) {
        int c = x;

        c += 1000;
        while (c > 2000)
            c -= 1000;
        return c;
    }

    // invokedynamic and synthetic method
    static int lambda(int x) {
        IntUnaryOperator f = v -> v + x;

        return f.applyAsInt(1);
    }

    static int stringSwitch(String s) {
        switch (s) {
        case "a":
            return 1;
        case "bb":
            return 2;
        default:
            return 0;
        }
    }

    record Point(int x, int y) {}

    static int record(int a) {
        Point p = new Point(a, 2);

        return p.x() + p.y();
    }

    static String patternSwitch(Object o) {
        return switch (o) {
        case Integer i when i > 5 -> "big";
        case Integer i -> "int";
        case String s -> "str";
        default -> "other";
        };
    }

    @Target(ElementType.TYPE_USE)
    @Retention(RetentionPolicy.RUNTIME)
    @interface Ann {}

    // local variable tables and type annotations in the Code attribute
    static int generics(List<String> l) {
        @Ann List<@Ann String> copy = new ArrayList<@Ann String>(l);
        int n = 0;

        for (@Ann String s : copy)
            n += s.length();
        return n;
    }

    // abstract and native methods are not instrumented
    abstract static class Abs {
        abstract int a();

        int b() {
            return a() + 1;
        }
    }

    static class Impl extends Abs {
        int a() {
            return 41;
        }
    }

    static native int nativeMethod();

    static int abstractMethod() {
        return new Impl().b();
    }
}
