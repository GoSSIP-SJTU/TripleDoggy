// Test that the tool can handle multiple parameters.
// RUN: %clang-display-context -line=6 -column=27 -line=11 -column=27 -line=16 -column=34 -line=22 -column=29 -line=26 -column=29 -line=33 -column=33 -line=40 -column=29 -line=46 -column=29 -line=51 -column=29 -line=56 -column=29 -line=63 -column=27 -line=68 -column=29 -line=74 -column=27 -line=80 -column=29 -line=86 -column=27 -line=92 -column=29 -line=100 -column=29 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 > %t
// RUN: FileCheck --input-file=%t %s

// Test that the input order does not matter.
// RUN: %clang-display-context -line=11 -line=26 -column=27 -column=29 -line=6 -column=27 -line=33 -column=33 -line=40 -column=29 -line=46 -column=29 -line=51 -column=29 -line=22 -column=29 -line=56 -column=29 -line=63 -column=27 -line=68 -column=29 -line=74 -column=27 -line=80 -column=29 -line=16 -column=34 -line=86 -column=27 -line=92 -column=29 -line=100 -column=29 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 > %t
// RUN: FileCheck --input-file=%t %s

// Test if Static Analyzer outputs the same.
// RUN: %clang_cc1 -analyze -std=c++11 -analyzer-checker=debug.ExprInspection %S/Inputs/test.cpp 2>&1 | FileCheck %s

// Test if the tool can find multiple bugs in the same line.
// RUN: %clang-display-context -line=105 -column=5 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 | FileCheck -check-prefix=CHECK-LAMBDA1 %s
// RUN: %clang-display-context -line=105 -column=30 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 | FileCheck -check-prefix=CHECK-LAMBDA2 %s

// Test invalid input parameters.
// RUN: not %clang-display-context -line=-1 -column=30 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 2>&1 | FileCheck -check-prefixes=CHECK-INVALID-LINE %s
// RUN: not %clang-display-context -line=105 -column=-1 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 2>&1 | FileCheck -check-prefix=CHECK-INVALID-COL %s
// RUN: not %clang-display-context -line=-1 -column=-1 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 2>&1 | FileCheck -check-prefixes=CHECK-INVALID-LINE,CHECK-INVALID-COL %s
// RUN: %clang-display-context -line=500000 -column=30 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 | FileCheck -check-prefix=CHECK-INVALID %s
// RUN: %clang-display-context -line=105 -column=500000 %S/Inputs/test.cpp -- %clang_cc1 -std=c++11 | FileCheck -check-prefix=CHECK-INVALID %s

// CHECK-DAG: void function(int)$27$clang_analyzer_hashDump(5);
// CHECK-DAG: void (anonymous namespace)::variadicParam(int, ...)$27$clang_analyzer_hashDump(5);
// CHECK-DAG: int f()$34$returnclang_analyzer_hashDump(5);
// CHECK-DAG: AA::X::X()$29$clang_analyzer_hashDump(5);
// CHECK-DAG: void AA::X::static_method()$29$clang_analyzer_hashDump(5);
// CHECK-DAG: void AA::X::method()::Y::method() const &$33$clang_analyzer_hashDump(5);
// CHECK-DAG: void AA::X::method() &&$29$clang_analyzer_hashDump(5);
// CHECK-DAG: class AA::X & AA::X::operator=(int)$29$clang_analyzer_hashDump(5);
// CHECK-DAG: AA::X::operator int()$29$clang_analyzer_hashDump(5);
// CHECK-DAG: AA::X::operator float()$29$clang_analyzer_hashDump(5);
// CHECK-DAG: void AA::X::OutOfLine()$27$clang_analyzer_hashDump(5);
// CHECK-DAG: void testLambda()::(anonymous class)::operator()() const$29$clang_analyzer_hashDump(5);
// CHECK-DAG: void f(T)$27$clang_analyzer_hashDump(5);
// CHECK-DAG: void TX::f(T)$29$clang_analyzer_hashDump(5);
// CHECK-DAG: void f(long)$27$clang_analyzer_hashDump(5);
// CHECK-DAG: void TX<long>::f(long)$29$clang_analyzer_hashDump(5);
// CHECK-DAG: void TTX::f(T, S)$29$clang_analyzer_hashDump(5);

// CHECK-LAMBDA1: void testLambda(_Bool)$5$1/[&](){returncoin?1/0:0;}();
// CHECK-LAMBDA2: int testLambda(bool)::(anonymous class)::operator()() const$30$1/[&](){returncoin?1/0:0;}();

// CHECK-INVALID-LINE: clang-display-context: for the -line option: '-1' value invalid for uint argument!
// CHECK-INVALID-COL: clang-display-context: for the -column option: '-1' value invalid for uint argument!
// CHECK-INVALID: Line {{[0-9]+}} and column {{[0-9]+}} do not specify an issue.

