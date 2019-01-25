// RUN: rm -rf %t && mkdir %t
// RUN: mkdir -p %t/ctudir2
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu -emit-pch -o %t/ctudir2/ctu-other.c.ast %S/Inputs/ctu-other.c
// RUN: cp %S/Inputs/externalFnMap2.txt %t/ctudir2/externalFnMap.txt
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu -fsyntax-only -std=c89 -analyze -analyzer-checker=core,debug.ExprInspection  -analyzer-config experimental-enable-naive-ctu-analysis=true -analyzer-config ctu-dir=%t/ctudir2 -verify %s

void clang_analyzer_eval(int);

typedef struct {
  int a;
  int b;
} foobar;

static int s1 = 21;

int f(int);
int enumcheck(void);
int static_check(void);

enum A { x,
         y,
         z };

extern foobar fb;

int getkey();

int main() {
  clang_analyzer_eval(f(5) == 1);             // expected-warning{{TRUE}}
  clang_analyzer_eval(x == 0);                // expected-warning{{TRUE}}
  clang_analyzer_eval(enumcheck() == 42);     // expected-warning{{TRUE}}

  return getkey();
}

// Test reporting error in a macro.
struct S;
int g(struct S *);
void test_macro(void) {
  g(0); // expected-warning@Inputs/ctu-other.c:31 {{Access to field 'a' results in a dereference of a null pointer (loaded from variable 'ctx')}}
}

// The external function prototype is incomplete.
// warning:implicit functions are prohibited by c99
void test_implicit(){
    int res=ident_implicit(6);// external implicit functions are not inlined
    clang_analyzer_eval(res == 6); // expected-warning{{TRUE}}
}


// Tests the import of functions that have a struct parameter
// defined in its prototype.
struct data_t{int a;int b;};
int struct_in_proto(struct data_t *d);
void test_struct_def_in_argument(){
  struct data_t d;
  d.a=1;
  d.b=0;
  clang_analyzer_eval(struct_in_proto(&d)==0);// expected-warning{{UNKNOWN}}
}
