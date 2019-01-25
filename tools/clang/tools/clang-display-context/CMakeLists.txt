set(LLVM_LINK_COMPONENTS support)

add_clang_executable(clang-display-context
  ClangDisplayContext.cpp
  )

target_link_libraries(clang-display-context
  PRIVATE
  clangTooling
  clangAST
  clangBasic
  clangFrontend
  clangLex
  clangStaticAnalyzerCore
  )

install(TARGETS clang-display-context
  RUNTIME DESTINATION bin)

