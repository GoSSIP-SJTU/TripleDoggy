// The tests which use this file are line and column sensitive.

constexpr int clang_analyzer_hashDump(int) { return 5; }

void function(int) {
  clang_analyzer_hashDump(5);
}

namespace {
void variadicParam(int, ...) {
  clang_analyzer_hashDump(5);
}
} // namespace

constexpr int f() {
  return clang_analyzer_hashDump(5);
}

namespace AA {
class X {
  X() {
    clang_analyzer_hashDump(5);
  }

  static void static_method() {
    clang_analyzer_hashDump(5);
    variadicParam(5);
  }

  void method() && {
    struct Y {
      inline void method() const & {
        clang_analyzer_hashDump(5);
      }
    };

    Y y;
    y.method();

    clang_analyzer_hashDump(5);
  }

  void OutOfLine();

  X &operator=(int) {
    clang_analyzer_hashDump(5);
    return *this;
  }

  operator int() {
    clang_analyzer_hashDump(5);
    return 0;
  }

  explicit operator float() {
    clang_analyzer_hashDump(5);
    return 0;
  }
};
} // namespace AA

void AA::X::OutOfLine() {
  clang_analyzer_hashDump(5);
}

void testLambda() {
  []() {
    clang_analyzer_hashDump(5);
  }();
}

template <typename T>
void f(T) {
  clang_analyzer_hashDump(5);
}

template <typename T>
struct TX {
  void f(T) {
    clang_analyzer_hashDump(5);
  }
};

template <>
void f<long>(long) {
  clang_analyzer_hashDump(5);
}

template <>
struct TX<long> {
  void f(long) {
    clang_analyzer_hashDump(5);
  }
};

template <typename T>
struct TTX {
  template<typename S>
  void f(T, S) {
    clang_analyzer_hashDump(5);
  }
};

void testLambda(bool coin) {
  1 / [&]() { return coin ? 1/0 : 0; }();
}

void g() {
  // TX<int> and TX<double> is instantiated from the same code with the same
  // source locations. The same error happining in both of the instantiations
  // should share the common hash. This means we should not include the
  // template argument for these types in the function signature.
  // Note that, we still want the hash to be different for explicit
  // specializations.
  TX<int> x;
  TX<double> y;
  TX<long> xl;
  x.f(1);
  xl.f(1);
  f(5);
  f(3.0);
  y.f(2);
  TTX<int> z;
  z.f<int>(5, 5);
  f(5l);
}

