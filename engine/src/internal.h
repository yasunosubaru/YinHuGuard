// engine/src/internal.h
//
// 引擎内部共享工具。不进 include/，不参与 C ABI —— Dart 只认 yh_engine.h 的
// extern "C" 符号，这里是实现侧的东西。
//
// 放进来的四类：
//   1) 编码：UTF-8 <-> UTF-16，严格模式，非法序列一律失败（locator 不能是乱码）
//   2) 内存：DupUtf8 —— 分配 yh_string_free 能释放的块
//   3) 错误：C ABI 没有异常，靠进程内最近一次错误文本把原因送回 Dart
//   4) 装配：AppendFinding —— 往 YhFindingList 追加，失败必须能被调用方看见

#ifndef YH_INTERNAL_H_
#define YH_INTERNAL_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "yh_engine.h"

namespace yh {
namespace internal {

// ---- 1) 编码 -------------------------------------------------------------

// 只转 ASCII 大写字母。中文等非 ASCII 原样保留：路径两侧走同一条转换，不会因
// Unicode 大小写规则不同而错配，也就不需要完整的 Unicode 大小写表。
std::string ToLowerAscii(const std::string& s);

bool IsSpace(char c);

// 两个方向都用 MB_ERR_INVALID_CHARS / 严格模式：非法 UTF-8 一律转换失败，
// 绝不返回带替换字符的路径——那会让 locator 变成看似正常的乱码。
// 失败时返回空串，调用方据此记 covered=0。
std::wstring Utf8ToWide(const std::string& utf8);
std::string WideToUtf8(const std::wstring& wide);

// ---- 2) 内存 -------------------------------------------------------------

// 分配一块 yh_string_free 能释放的 UTF-8 C 串。分配失败返回 nullptr。
char* DupUtf8(const std::string& s);

// ---- 3) 错误 -------------------------------------------------------------

// 记录最近一次错误。空文本表示清除。
void SetLastErrorText(const std::string& text);
const char* GetLastErrorText();

// 当前进程是否已提权。GetTokenInformation(TokenElevation)。
bool IsElevated();

// ---- 4) 装配 -------------------------------------------------------------

// 追加一条发现。任意一次分配失败即返回 false（调用方必须清理已有条目并返回
// 分配失败码，不能返回半份结果）。list 必须已零初始化。
bool AppendFinding(YhFindingList* list, const char* locator, const char* display_name,
                   const char* criteria, bool attributes_verified, bool hidden, bool system,
                   bool elevation_required, bool covered);

// 释放 list 内全部字符串与数组本身，并把它重置为零状态（幂等）。
void FreeFindingList(YhFindingList* list);

// 当前 unix 秒，作为发现的时间戳。
double UnixSecondsNow();

// 进程扫描的聚合计数。self_check 需要它与 scan_processes 完全同源——
// 两份实现会漂移，而「未覆盖」这件事正是靠这些计数才看得见。
struct ProcessScanSummary {
  int32_t process_total = 0;
  int32_t process_path_resolved = 0;
  int32_t session0_visible = 0;
};

// 枚举进程。findings 为 nullptr 时只统计不产出发现。
// 返回 0 成功，2 分配失败。
int32_t ScanProcesses(ProcessScanSummary* summary, YhFindingList* findings);

// 枚举三个 Run 键。「扫描2/3」。
int32_t ScanRunKeys(YhFindingList* findings);

// 枚举服务并判可疑。「扫描3/3」。需要配置的判据集合与硬白名单。
struct ServiceScanOptions {
  const std::vector<std::string>* interpreter_keywords = nullptr;
  const std::vector<std::string>* path_allow_prefixes = nullptr;
  const std::vector<std::string>* hard_allowlist = nullptr;
};

// 汇总计数，供 self_check 与 scan_services 同源使用。
struct ServiceScanSummary {
  int32_t services_total = 0;
  int32_t services_with_path = 0;
};

int32_t ScanServices(const ServiceScanOptions& options, ServiceScanSummary* summary,
                     YhFindingList* findings);

}  // namespace internal
}  // namespace yh

#endif  // YH_INTERNAL_H_
