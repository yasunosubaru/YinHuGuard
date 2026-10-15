// engine/include/yh_criteria.h
//
// 判据纯函数：输入字符串或整数，输出布尔或字符串。
// 这里不碰进程、服务、注册表、文件系统——全部 Win32 访问在 Task 3 的扫描器里。
//
// 声明照 plan 的 Interfaces 块逐字给出；实现见 src/criteria.cpp。
// 任何签名改动都会同时影响 Task 3（扫描器）与其测试，故需先改 plan。

#ifndef YH_CRITERIA_H_
#define YH_CRITERIA_H_

#include <cstdint>
#include <string>
#include <vector>

namespace yh {

// 等价上游 findstr /i "h s"：FILE_ATTRIBUTE_HIDDEN(0x2) 或 FILE_ATTRIBUTE_SYSTEM(0x4)
bool has_hidden_or_system(uint32_t file_attributes);

// 上游 :ScanRun 的值数据解析回退链，完整复刻
std::string extract_run_value_path(const std::string& reg_value_data);

// 展开 %VAR% 与 %VAR%（未知变量保持原样，不报错）
std::string expand_env_vars(const std::string& path, bool* expanded_ok);

// 剥掉首尾引号与第一个参数段："C:\a\b.exe" -k netsvcs -> C:\a\b.exe
std::string strip_quotes_and_args(const std::string& image_path);

// 解释器关键字匹配，大小写不敏感；keywords 为固定六元集合
bool matches_interpreter(const std::string& image_path,
                         const std::vector<std::string>& keywords);

// 路径前缀判定，大小写不敏感，边界必须是目录分隔符
bool path_in_prefixes(const std::string& image_path,
                      const std::vector<std::string>& prefixes);

// 硬白名单 + 用户白名单。命中返回 true → 该条目不产生发现
bool is_hard_allowlisted(const std::string& name,
                         const std::vector<std::string>& hard_allowlist);

// 服务 ImagePath 的归类：返回 "service_interpreter" / "service_path_heuristic"，
// 干净服务返回空串。
//
// **这个函数存在的唯一理由就是不让那两条判据被分别调用。**
// 曾经把 strip_quotes_and_args 的结果喂给 matches_interpreter，而它会截断到
// 第一个空格、把 `/c` 删掉 —— 于是 `cmd.exe /c a.bat` 匹配不到、落到路径前缀
// 判定、前缀又在 System32 里，最后静默丢掉。两个单元函数各自都对，
// 测试分开跑也都绿，错只存在于它们的组合里，而组合只存在于那个不能在本机
// 运行的扫描文件里。所以组合必须搬到这里，由单元测试盯着。
//
// image_path 传**原始**值，不要预剥：matches_interpreter 需要看到 `/c`
// （spec §4.3），path_in_prefixes 自己会剥。
std::string classify_service_path(const std::string& image_path,
                                  const std::vector<std::string>& interpreter_keywords,
                                  const std::vector<std::string>& path_allow_prefixes);

}  // namespace yh

#endif  // YH_CRITERIA_H_
