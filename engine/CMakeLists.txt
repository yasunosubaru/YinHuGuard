# engine/CMakeLists.txt
#
# 引擎共享库 + 判据单元测试。只支持 Windows x64：项目全程走 Win32 x64，
# 任何别的目标架构都在配置阶段直接拒绝，不留到链接或运行期才炸。

cmake_minimum_required(VERSION 3.20)
project(yinhuguard_engine LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "YinHuGuard 引擎只支持 Windows，当前不是 Windows。")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "YinHuGuard 引擎只支持 x64：当前目标位宽不是 8 字节。")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 源文件与注释里有中文。MSVC 默认按系统代码页读源文件，会把中文注释编成乱码，
# 连带污染任何事后按 UTF-8 读取的检查。这里全局设置，将来 Task 3 新加的源文件
# 自动继承，不会因为漏写一行而返工。
# 只加编译期选项：link.exe 不认 /utf-8，交给它会得到 LNK4044
# 「无法识别的选项 /utf-8；已忽略」，每条链接命令都带一条警告。字面量在编译期
# 就已编进目标文件，链接期无需再声明字符集。
add_compile_options(/utf-8)

# CONFIGURE_DEPENDS：Task 3 往 src/ 加 processes.cpp / run_keys.cpp / services.cpp /
# self_check.cpp / engine.cpp 时会被自动重新纳入，裸 GLOB 则要求手动重跑配置。
file(GLOB ENGINE_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(yinhuguard_engine SHARED ${ENGINE_SOURCES})
target_include_directories(yinhuguard_engine PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# brief 里「Windows 上默认全导出」的说法与 MSVC 实际行为相反：MSVC 的 DLL 默认
# 一个符号都不导出。显式打开全导出，Task 3 的 dumpbin 导出表检查与 Dart 侧
# FFI 绑定才有符号可用；这也是平台无关 CMake 里对应的等效设置。
# 代价：导出表会连带导出大量 std:: 内部符号。C++ 名字被修饰成
# `?expand_env_vars@yh@@...`，不含 "yh_" 子串，所以 Task 3 的
# `dumpbin /exports | findstr yh_` 仍然只匹配那八个 C 符号。
# 若将来想收紧导出面，改用 .def 显式列出八个符号即可。
set_target_properties(yinhuguard_engine PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

# 单元测试直接编译 src/ 而不是链共享库：这样测的是源码本身的行为，
# 不受 DLL 导出表配置变动影响，编译也更快。导出表的验证归 Task 3 的 dumpbin 步骤。
# test_criteria 必须在 assert 生效的配置下编译：Release 默认带 /DNDEBUG，会把全部
# assert 编译成空语句，测试就变成恒过的空跑。放在 add_executable 之前改
# CMAKE_CXX_FLAGS_RELEASE，只影响其后创建的目标（共享库保留 /DNDEBUG，它里面
# 没有 assert）。比事后追加 /UNDEBUG 少一条 cl 的 D9025「正在重写」提示。
string(REPLACE "/DNDEBUG" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

add_executable(test_criteria
  tests/test_criteria.cpp
  src/criteria.cpp
  src/config.cpp
)
target_include_directories(test_criteria PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")

enable_testing()
add_test(NAME test_criteria COMMAND test_criteria)