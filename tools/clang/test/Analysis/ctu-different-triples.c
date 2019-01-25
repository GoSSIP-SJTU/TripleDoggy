// RUN: rm -rf %t && mkdir %t
// RUN: mkdir -p %t/ctudir3
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu -emit-pch -o %t/ctudir3/ctu-other.c.ast %S/Inputs/ctu-other.c
// RUN: cp %S/Inputs/externalFnMap2.txt %t/ctudir3/externalFnMap.txt
// RUN: %clang_cc1 -triple powerpc64-montavista-linux-gnu -fsyntax-only -std=c89 -analyze -analyzer-checker=core,debug.ExprInspection -analyzer-config experimental-enable-naive-ctu-analysis=true -analyzer-config ctu-dir=%t/ctudir3 -verify %s

// We expect an error in this file, but without a location.
// expected-error-re@./ctu-different-triples.c:*{{imported AST from {{.*}} had been generated for a different target, current: powerpc64-montavista-linux-gnu, imported: x86_64-pc-linux-gnu}}

int f(int);

int main() {
  return f(5); // TODO expect the error here at the CallExpr location
}
