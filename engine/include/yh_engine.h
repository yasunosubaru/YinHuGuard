// engine/include/yh_engine.h
//
// 引擎对外接口的骨架。Task 1 只放配置加载；spec §3.1 的 C ABI 与三个扫描函数
// 由 Task 3 补齐，Dart 侧只认 extern "C" 的那八个符号。
//
// 本文件是共享库与测试共同包含的头，include/ 是 PUBLIC include 目录。

#ifndef YH_ENGINE_H_
#define YH_ENGINE_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace yh {

// rules.json（spec §8）的内存形态，字段与文件里的键一一对应。
// 这里是完整定义而非前向声明：load_config 返回 std::unique_ptr<Config>，
// 任何拿到它的调用方（Task 3 的 engine.cpp 与 test_config.cpp）都要能析构它，
// 而 unique_ptr 的默认删除器要求类型完整。
struct Config {
  int schema_version = 0;
  std::string updated_at;  // spec §8 有此键，但校验清单未要求，缺失不拒
  std::vector<std::string> service_interpreter_keywords;
  std::vector<std::string> service_path_allow_prefixes;
  std::vector<std::string> process_allowlist;
  std::vector<std::string> hard_allowlist;
  std::vector<std::string> system_process_names;
};

// 读并校验 rules.json。任一项不合法即返回 nullptr，并把**具体不合法或缺失的键名**
// 写进 *error（error 可为 nullptr）。
// spec §2 硬约束 3：配置是纯数据，非法配置必须拒绝加载并明确报错，不静默降级。
std::unique_ptr<Config> load_config(const std::string& path, std::string* error);

}  // namespace yh

// ===========================================================================
// C ABI（spec §3.1）。Dart 侧只认这一层。
//
// 三个 POD 结构的字段**顺序即 ABI**：Dart 按偏移读，顺序错了不会编译报错，
// 只会在运行期读出垃圾。x64 下 YhFinding = 56 字节（3 指针 24 + 5 个 int32 20
// 补齐到 48 + double 8）。test/bindings_layout_test.dart 把这三个尺寸钉死。
//
// 返回码：0 = 成功，1 = 配置无效，2 = 分配失败。
// 全部 char* 为 UTF-8，由 yh_string_free 释放。
// ===========================================================================

extern "C" {

typedef struct {
  char* locator;             // 进程完整路径 / 注册表键路径 / 服务名
  char* display_name;        // 界面展示用
  char* criteria;            // "file_attr_hs" | "service_interpreter" | "service_path_heuristic"
  int32_t attributes_verified;  // 0 = 属性未知
  int32_t hidden;
  int32_t system;
  int32_t elevation_required;
  int32_t covered;           // 0 = 因权限不足未覆盖
  double timestamp;          // unix 秒
} YhFinding;

typedef struct {
  YhFinding* items;
  size_t count;
} YhFindingList;

typedef struct {
  int32_t elevated;
  int32_t process_total;
  int32_t process_path_resolved;
  int32_t session0_visible;   // 非提权时应为 0 —— UI 靠它显示「未覆盖」
  int32_t services_total;
  int32_t services_with_path;
} YhSelfCheck;

// 读配置并建引擎。配置非法返回 nullptr，原因经 yh_last_error 取。
// 配置非法的原因必须能到界面（spec §2 硬约束 3 要求明确报错而不是静默降级），
// 所以引擎额外导出 yh_last_error 这一个取值函数——否则「指名键名」无从传达。
void* yh_engine_create(const char* config_path);
void yh_engine_destroy(void* handle);

// 自检：实测各项数据源的可达性，用于暴露 FFI/枚举在真机上静默失效的情况。
int32_t yh_self_check(void* handle, YhSelfCheck* out);

// 三段扫描，与上游 bat 的三段一一对应。
int32_t yh_scan_processes(void* handle, YhFindingList* out);
int32_t yh_scan_run_keys(void* handle, YhFindingList* out);
int32_t yh_scan_services(void* handle, YhFindingList* out);

// 进程内最近一次错误的 UTF-8 文本；无错误时返回空串。不要 free 它。
const char* yh_last_error(void);

// 释放 yh_scan_* 产出的列表内容与数组本身（幂等）。
void yh_finding_list_free(YhFindingList* list);

// 释放引擎产出的单个字符串。
void yh_string_free(char* s);

}  // extern "C"

// ---------------------------------------------------------------------------
// 布局断言。**这是 C/Dart 之间唯一一道会主动报警的防线。**
//
// 字段顺序错了不会编译报错，只会在运行期把 locator 读成 display_name 的内容，
// 或者把指针当整数读出来 —— 报告里就出现一堆乱码路径，而「乱码文件名」正是
// 银狐的民间判据，于是编码错误会直接伪造出一个看起来很像的命中。
//
// Dart 侧的 test/bindings_layout_test.dart 只断言 sizeOf，而那个数字在把三个
// 指针互相换位、把五个 int32 任意重排之后都不变。所以偏移必须在 C 这边钉死 ——
// 这一侧改了会立刻编译失败，比运行期才发现强得多。
// ---------------------------------------------------------------------------

static_assert(sizeof(YhFinding) == 56, "YhFinding 必须是 56 字节（x64）");

static_assert(offsetof(YhFinding, locator) == 0, "YhFinding.locator 偏移必须为 0");
static_assert(offsetof(YhFinding, display_name) == 8, "YhFinding.display_name 偏移必须为 8");
static_assert(offsetof(YhFinding, criteria) == 16, "YhFinding.criteria 偏移必须为 16");
static_assert(offsetof(YhFinding, attributes_verified) == 24,
              "YhFinding.attributes_verified 偏移必须为 24");
static_assert(offsetof(YhFinding, hidden) == 28, "YhFinding.hidden 偏移必须为 28");
static_assert(offsetof(YhFinding, system) == 32, "YhFinding.system 偏移必须为 32");
static_assert(offsetof(YhFinding, elevation_required) == 36,
              "YhFinding.elevation_required 偏移必须为 36");
static_assert(offsetof(YhFinding, covered) == 40, "YhFinding.covered 偏移必须为 40");
static_assert(offsetof(YhFinding, timestamp) == 48,
              "YhFinding.timestamp 偏移必须为 48（double 需 8 字节对齐，中间补 4 字节）");

static_assert(sizeof(YhFindingList) == 16, "YhFindingList 必须是 16 字节（x64）");
static_assert(offsetof(YhFindingList, items) == 0, "YhFindingList.items 偏移必须为 0");
static_assert(offsetof(YhFindingList, count) == 8, "YhFindingList.count 偏移必须为 8");

static_assert(sizeof(YhSelfCheck) == 24, "YhSelfCheck 必须是 24 字节");
static_assert(offsetof(YhSelfCheck, elevated) == 0, "YhSelfCheck.elevated 偏移必须为 0");
static_assert(offsetof(YhSelfCheck, process_total) == 4, "YhSelfCheck.process_total 偏移必须为 4");
static_assert(offsetof(YhSelfCheck, process_path_resolved) == 8,
              "YhSelfCheck.process_path_resolved 偏移必须为 8");
static_assert(offsetof(YhSelfCheck, session0_visible) == 12,
              "YhSelfCheck.session0_visible 偏移必须为 12");
static_assert(offsetof(YhSelfCheck, services_total) == 16,
              "YhSelfCheck.services_total 偏移必须为 16");
static_assert(offsetof(YhSelfCheck, services_with_path) == 20,
              "YhSelfCheck.services_with_path 偏移必须为 20");

#endif  // YH_ENGINE_H_
