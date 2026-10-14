// engine/tests/test_criteria.cpp
//
// 判据纯函数单元测试。全部用例只操作字符串和整数——不枚举进程、不查服务、
// 不读注册表、不访问文件系统，因此不触碰本机真实系统状态。
//
// spec §8 固定的六元解释器关键字与两个服务路径允许前缀在此写死：
// 任何增删都必须先改 spec 与本文件。

#include "yh_criteria.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// Release 配置默认带 /DNDEBUG，会把全部 assert 编译成空语句，测试变成恒过的空跑。
// engine/CMakeLists.txt 已在创建本目标前把 /DNDEBUG 从 Release flags 里去掉，
// 这里再兜一层编译期底，防止后人换工具链或改配置时静默失去全部断言。
#ifdef NDEBUG
#error "test_criteria 必须在 assert 生效的配置下编译（检查 CMake 里的 NDEBUG 处理）"
#endif

namespace {

// brief 的断言按裸名书写，这里一次性把 yh 引进当前作用域，断言原文不改
using namespace yh;

// ---- spec §8 固定集合（测试侧不读配置文件，避免把配置错误混进判据测试）----

std::vector<std::string> InterpreterKeywords() {
  return {"cmd /c", "powershell", "wscript", "cscript", "mshta", "pwsh"};
}

std::vector<std::string> ServicePathPrefixes() {
  return {"C:\\Windows\\System32", "C:\\Windows\\SysWOW64"};
}

std::vector<std::string> HardAllowlistNames() {
  return {"swprv", "vmservice", "MicrosoftSoftware2ShadowCop4yProvider"};
}

// ---- 用例 ----------------------------------------------------------------

// Review Focus #4：带引号带参数仍要命中，且剥出干净路径
void test_strip_quotes_and_args() {
  assert(strip_quotes_and_args("\"C:\\a\\sv.exe\" -k netsvcs") == "C:\\a\\sv.exe");
  assert(strip_quotes_and_args("C:\\a\\sv.exe -k netsvcs") == "C:\\a\\sv.exe");
  // 无参数路径原样返回
  assert(strip_quotes_and_args("C:\\a\\sv.exe") == "C:\\a\\sv.exe");
  // 只有引号没有参数
  assert(strip_quotes_and_args("\"C:\\a\\sv.exe\"") == "C:\\a\\sv.exe");
  // 空输入（服务 PathName 为空的情形）
  assert(strip_quotes_and_args("") == "");
}

// 解释器关键字：spec §8 固定六元集合，逐个正例 + 三个负例
void test_matches_interpreter() {
  const std::vector<std::string> kw = InterpreterKeywords();

  assert(matches_interpreter("C:\\Windows\\System32\\cmd.exe /c foo.bat", kw));  // cmd /c
  assert(matches_interpreter(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc AAAA", kw));
  assert(matches_interpreter("C:\\Windows\\System32\\wscript.exe C:\\a\\b.vbs", kw));
  assert(matches_interpreter("C:\\Windows\\System32\\cscript.exe C:\\a\\b.js", kw));
  assert(matches_interpreter("C:\\Windows\\mshta.exe http://x", kw));
  assert(matches_interpreter("C:\\Program Files\\PowerShell\\7\\pwsh.dll", kw));

  assert(!matches_interpreter("C:\\Windows\\System32\\svchost.exe -k netsvcs", kw));
  assert(!matches_interpreter("C:\\Windows\\System32\\services.exe", kw));
  assert(!matches_interpreter("C:\\Windows\\System32\\cmd.exe", kw));  // 无 "/c" 不命中

  // Review Focus #4：带引号带参数仍要命中，且剥出干净路径
  assert(matches_interpreter("\"C:\\a\\cmd.exe\" /c x.bat", kw));

  // 多词关键字按「词序」匹配：cmd 必须在 /c 之前，反序不算命中
  assert(!matches_interpreter("/c C:\\Windows\\System32\\cmd.exe", kw));
  // 空关键字表不命中任何东西（配置被清空时不能变成「全部命中」）
  assert(!matches_interpreter("C:\\Windows\\System32\\cmd.exe /c", {}));
  // 表里混入空串同样不构成命中条件
  assert(!matches_interpreter("C:\\Windows\\System32\\cmd.exe /c", {""}));

  // 关键字大小写不敏感：rules.json 是用户手编的，写成 "PowerShell" 或 "CMD /C"
  // 不能让整条 service_interpreter 判据静默失效
  assert(matches_interpreter(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", {"PowerShell"}));
  assert(matches_interpreter("C:\\Windows\\System32\\cmd.exe /c foo.bat", {"CMD /C"}));
  assert(matches_interpreter("C:\\Windows\\System32\\cmd.exe /c foo.bat", {"cmd /C"}));
  assert(matches_interpreter("C:\\Windows\\mshta.exe http://x", {"MSHTA"}));

  // 关键字词必须落在词元上，而不是更长的子串里
  assert(!matches_interpreter("C:\\x\\mycmd.txt /c", kw));           // cmd 只是 mycmd 的一部分
  assert(!matches_interpreter("C:\\Windows\\System32\\cmd.exe /cleanup", kw));  // /c 是 /cleanup 的前缀
  assert(!matches_interpreter("C:\\x\\powershellnotes.txt", kw));     // powershell 只是长文件名的前缀
  // 但引号带参数的正常形态仍然命中（主干计算要剥掉引号）
  assert(matches_interpreter("\"C:\\a\\cmd.exe\" /c x.bat", kw));
}

// Review Focus #5：Run 值数据回退链
void test_extract_run_value_path() {
  assert(extract_run_value_path("\"C:\\a\\b.exe\" -s") == "C:\\a\\b.exe");
  assert(extract_run_value_path("C:\\a\\b.exe") == "C:\\a\\b.exe");
  assert(extract_run_value_path("\"%TEMP%\\x.exe\"") == "%TEMP%\\x.exe");
  assert(extract_run_value_path("C:\\a\\b.exe\")") == "C:\\a\\b.exe");  // 剥尾随 ')'
  assert(extract_run_value_path("") == "");

  // 只有起始引号、没有闭合引号：引号内取不到内容，退回整串再剥掉那个孤立引号
  assert(extract_run_value_path("\"C:\\a\\b.exe") == "C:\\a\\b.exe");
  // 无引号但带尾随 ')'：剥 ')' 单独生效（上游 reg query 噪声的典型残留）
  assert(extract_run_value_path("C:\\a\\b.exe)") == "C:\\a\\b.exe");
  // 剥 ')' 在取引号内容之前，所以外层成对引号里的 ')' 也能去掉
  assert(extract_run_value_path("\"C:\\a\\b.exe)\"") == "C:\\a\\b.exe");
}

// Review Focus #2：REG_EXPAND_SZ 的 %VAR% 必须先展开再判存在
void test_expand_env_vars() {
  bool ok = false;
  assert(expand_env_vars("C:\\Windows\\Temp\\x.exe", &ok) == "C:\\Windows\\Temp\\x.exe");
  assert(expand_env_vars("%TEMP%\\x.exe", &ok) == std::string(getenv("TEMP")) + "\\x.exe");
  assert(ok);
  assert(expand_env_vars("%NOSUCHVAR_XYZ%\\x.exe", &ok) == "%NOSUCHVAR_XYZ%\\x.exe");
  assert(!ok);  // 未知变量保持原样并标记未完全展开

  // 无 %VAR% 时不算「未完全展开」
  assert(expand_env_vars("C:\\Windows\\x.exe", &ok) == "C:\\Windows\\x.exe");
  assert(ok);
  // out 参数可空
  assert(expand_env_vars("%TEMP%\\x.exe", nullptr) ==
         std::string(getenv("TEMP")) + "\\x.exe");
}

// H/S 属性：spec §4.1 唯一判据
void test_has_hidden_or_system() {
  assert(has_hidden_or_system(0x2));          // HIDDEN
  assert(has_hidden_or_system(0x4));          // SYSTEM
  assert(has_hidden_or_system(0x6));          // HIDDEN|SYSTEM
  // brief 的用例块把这两行写成了无 `!` 的正例，但 0x20 是 ARCHIVE、
  // 0x1 是 READONLY，都不是 H/S。brief 自己的算法说明 `(attrs & 0x6) != 0`
  // 与 spec §4.1（只认 H 或 S）也都是否掉它们的，此处按 brief 的算法与
  // spec 修正。见 task-1-report.md「Issues or concerns」第 1 条。
  assert(!has_hidden_or_system(0x20));        // ARCHIVE
  assert(!has_hidden_or_system(0x20 | 0x1));  // ARCHIVE|READONLY
  assert(!has_hidden_or_system(0x0));
}

// 路径前缀：边界必须是目录分隔符
void test_path_in_prefixes() {
  const std::vector<std::string> pre = ServicePathPrefixes();
  assert(path_in_prefixes("C:\\Windows\\System32\\svchost.exe", pre));
  assert(path_in_prefixes("C:\\Windows\\SysWOW64\\cmd.exe", pre));
  assert(!path_in_prefixes("C:\\Windows\\System32X\\evil.exe", pre));  // 前缀误配
  assert(!path_in_prefixes("C:\\Users\\Public\\x.exe", pre));
  assert(path_in_prefixes("c:\\windows\\system32\\svchost.exe", pre));  // 大小写不敏感

  // Review Focus #4：服务 PathName 带引号和参数时，判定前必须先剥掉参数，
  // 否则每个带参数的系统服务都会被 service_path_heuristic 误报
  assert(path_in_prefixes("\"C:\\Windows\\System32\\svchost.exe\" -k netsvcs", pre));
  assert(!path_in_prefixes("\"C:\\Users\\Public\\x.exe\" -k mine", pre));
}

// 硬白名单：swprv 必须在
void test_is_hard_allowlisted() {
  const std::vector<std::string> hard = HardAllowlistNames();
  assert(is_hard_allowlisted("swprv", hard));
  assert(is_hard_allowlisted("MicrosoftSoftware2ShadowCop4yProvider", hard));
  assert(!is_hard_allowlisted("CleverSoar", hard));
  // vafdska / MiniFilterDrv 不是白名单项，也绝不能出现在配置里
  assert(!is_hard_allowlisted("vafdska", hard));

  // 大小写不敏感的全等比较，不是子串匹配
  assert(is_hard_allowlisted("VMSERVICE", hard));
  assert(is_hard_allowlisted("vmservice", hard));
  assert(!is_hard_allowlisted("my_vmservice", hard));
  assert(!is_hard_allowlisted("vmservice.exe", hard));
  // MiniFilterDrv 同样不在硬白名单
  assert(!is_hard_allowlisted("MiniFilterDrv", hard));
}

// ---- 运行器 --------------------------------------------------------------

using TestFn = void (*)();

struct TestCase {
  const char* name;
  TestFn fn;
};

const TestCase kCases[] = {
    {"strip_quotes_and_args", test_strip_quotes_and_args},
    {"matches_interpreter", test_matches_interpreter},
    {"extract_run_value_path", test_extract_run_value_path},
    {"expand_env_vars", test_expand_env_vars},
    {"has_hidden_or_system", test_has_hidden_or_system},
    {"path_in_prefixes", test_path_in_prefixes},
    {"is_hard_allowlisted", test_is_hard_allowlisted},
};

}  // namespace

int main() {
  int passed = 0;
  const int total = static_cast<int>(sizeof(kCases) / sizeof(kCases[0]));
  for (int i = 0; i < total; ++i) {
    // assert 失败会直接 abort（带文件行号），不会走到打印之后
    kCases[i].fn();
    ++passed;
    std::printf("[PASS] %s\n", kCases[i].name);
  }
  std::printf("%d/%d 用例通过\n", passed, total);
  return 0;
}
