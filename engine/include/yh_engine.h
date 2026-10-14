// engine/include/yh_engine.h
//
// 引擎对外接口的骨架。Task 1 只放配置加载；spec §3.1 的 C ABI 与三个扫描函数
// 由 Task 3 补齐，Dart 侧只认 extern "C" 的那八个符号。
//
// 本文件是共享库与测试共同包含的头，include/ 是 PUBLIC include 目录。

#ifndef YH_ENGINE_H_
#define YH_ENGINE_H_

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

#endif  // YH_ENGINE_H_
