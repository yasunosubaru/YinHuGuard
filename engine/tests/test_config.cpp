// engine/tests/test_config.cpp
//
// load_config 的单元测试。全部用例只读写**临时目录里由本测试自己创建的 json 文件**，
// 不读仓库里的 rules/rules.json，不碰任何真实系统状态（进程、服务、注册表一律不碰）。
//
// 用例编号沿用 plan Task 3 Step 1 约定的四个必测项（①-④），其余为补充分支。

#include "yh_criteria.h"
#include "yh_engine.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifdef NDEBUG
#error "test_config 必须在 assert 生效的配置下编译（检查 CMake 里的 NDEBUG 处理）"
#endif

namespace {

// 测试自己的沙箱目录：<系统临时目录>/yinhuguard_test_config。
// 不指向仓库，不指向用户数据。
std::filesystem::path SandboxDir() {
  return std::filesystem::temp_directory_path() / "yinhuguard_test_config";
}

// 写入一个测试用 json，返回其完整路径
std::string WriteTemp(const std::string& name, const std::string& body) {
  const std::filesystem::path path = SandboxDir() / name;
  std::ofstream out(path, std::ios::binary);
  out.write(body.data(), static_cast<std::streamsize>(body.size()));
  out.close();
  return path.string();  // narrow：临时目录路径是 ASCII，中文用例另有覆盖
}

int g_failures = 0;
int g_checks = 0;

void Check(bool condition, const std::string& what) {
  ++g_checks;
  if (condition) {
    std::printf("[PASS] %s\n", what.c_str());
  } else {
    std::printf("[FAIL] %s\n", what.c_str());
    ++g_failures;
  }
}

// 错误信息里必须指名键名——spec §2 硬约束 3 要求「明确错误」，不是一句「配置无效」
void CheckNames(const std::string& error, const std::string& key, const std::string& what) {
  ++g_checks;
  const bool ok = error.find(key) != std::string::npos;
  if (!ok) {
    ++g_failures;
    std::printf("[FAIL] %s\n       实际 error = %s\n", what.c_str(), error.c_str());
  } else {
    std::printf("[PASS] %s\n", what.c_str());
  }
}

// ---- 样本 ---------------------------------------------------------------

// 照 spec §8 的形状写的合法样本
const char* kValid = R"({
  "schema_version": 1,
  "updated_at": "2026-10-14",
  "service_interpreter_keywords": ["cmd /c", "powershell", "wscript", "cscript", "mshta", "pwsh"],
  "service_path_allow_prefixes": ["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"],
  "process_allowlist": ["explorer.exe", "svchost.exe", "lsass.exe"],
  "hard_allowlist": ["swprv", "vmservice", "MicrosoftSoftware2ShadowCop4yProvider"],
  "system_process_names": ["System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "conhost.exe",
    "sihost.exe", "dllhost.exe", "spoolsv.exe", "taskhostw.exe"]
})";

// 复用合法样本，把整个 "key": [...] 对连同尾随逗号一起删掉（留空数组不算缺键）
std::string WithoutKey(const char* key) {
  const std::string full = kValid;
  const std::string begin = std::string("  \"") + key + "\"";
  const size_t at = full.find(begin);
  if (at == std::string::npos) {
    return std::string();
  }
  const size_t value_at = full.find(':', at) + 1;
  int depth = 0;
  size_t i = value_at;
  for (; i < full.size(); ++i) {
    if (full[i] == '[') ++depth;
    if (full[i] == ']') --depth;
    if (depth == 0 && full[i] == ',') {
      ++i;  // 连同这个逗号一起删
      break;
    }
  }
  return full.substr(0, at) + full.substr(i);
}

// 复用合法样本，把某个键的值整体换成给定的字面量
std::string WithValue(const char* key, const std::string& literal) {
  const std::string full = kValid;
  const size_t at = full.find(std::string("  \"") + key + "\"");
  const size_t value_at = full.find(':', at) + 1;
  int depth = 0;
  size_t i = value_at;
  for (; i < full.size(); ++i) {
    if (full[i] == '[') ++depth;
    if (full[i] == ']') --depth;
    if (depth == 0 && full[i] == ',') {
      break;
    }
  }
  return full.substr(0, value_at) + literal + full.substr(i);
}

// ---- 用例 ----------------------------------------------------------------

// plan Task 3 Step 1 的四个必测项
void test_task3_required_cases() {
  {
    const std::string path = WriteTemp("rules_valid.json", kValid);
    std::string error = "（未被清空，说明失败路径没走）";
    std::unique_ptr<yh::Config> config = yh::load_config(path, &error);
    Check(config != nullptr, "① 合法样本加载成功");
    Check(error.empty(), "① 成功时 error 被清空");
    if (config) {
      Check(config->schema_version == 1, "① schema_version == 1");
      Check(config->updated_at == "2026-10-14", "① updated_at 解析正确");
      Check(config->service_interpreter_keywords.size() == 6, "① 六个解释器关键字");
      Check(config->service_interpreter_keywords[0] == "cmd /c", "① 反斜杠转义后的 cmd /c 正确");
      Check(config->service_path_allow_prefixes.size() == 2, "① 两个允许前缀");
      Check(config->service_path_allow_prefixes[0] == "C:\\Windows\\System32",
            "① 单反斜杠的 \\W 按 JSON 规则解析");
      Check(config->hard_allowlist.size() == 3, "① 三个硬白名单项（与下限去重后仍是三个）");
      Check(config->system_process_names.size() == 14, "① 14 个系统进程名（跨行数组）");
      Check(config->process_allowlist.size() == 3, "① 三个用户白名单项");
    }
  }
  {
    const std::string path = WriteTemp("rules_nokw.json", WithoutKey("service_interpreter_keywords"));
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "② 缺 service_interpreter_keywords 拒绝加载");
    CheckNames(error, "service_interpreter_keywords", "② error 指名 service_interpreter_keywords");
  }
  {
    const std::string path =
        WriteTemp("rules_oneprefix.json", WithValue("service_path_allow_prefixes", "[\"C:\\\\Windows\\\\System32\"]"));
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "③ 允许前缀只有一项时拒绝加载");
    CheckNames(error, "service_path_allow_prefixes", "③ error 指名 service_path_allow_prefixes");
  }
  {
    std::string bad = kValid;
    bad.replace(bad.find("\"schema_version\": 1"), std::string("\"schema_version\": 1").size(),
                "\"schema_version\": 2");
    const std::string path = WriteTemp("rules_schema2.json", bad);
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "④ 未知 schema_version 拒绝加载");
    CheckNames(error, "schema_version", "④ error 指名 schema_version");
  }
}

// 解析器分支：转义、BOM、未知键、重复键、类型错误
void test_parser_branches() {
  {
    std::string body = kValid;
    body.insert(0, "\xEF\xBB\xBF");  // Windows 编辑器默认会写 BOM
    const std::string path = WriteTemp("rules_bom.json", body);
    std::string error;
    Check(yh::load_config(path, &error) != nullptr, "带 UTF-8 BOM 仍能加载");
  }
  {
    const std::string bad = WithValue("hard_allowlist", "[\"swprv\", 7, \"vmservice\"]");
    const std::string path = WriteTemp("rules_nonstring.json", bad);
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "数组里有非字符串项时拒绝加载");
    CheckNames(error, "hard_allowlist", "非字符串项的 error 指名所在键");
  }
  {
    std::string bad = kValid;
    bad.insert(bad.find("\"system_process_names\""), "\"hard_allowlist\": [\"x\"], ");
    const std::string path = WriteTemp("rules_dup.json", bad);
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "重复键拒绝加载");
    CheckNames(error, "hard_allowlist", "重复键的 error 指名该键");
  }
  {
    const std::string extra =
        WithValue("hard_allowlist", "[\"swprv\"]");  // 占位，下面再加未知键
    std::string body = extra;
    body.insert(body.find("\"updated_at\""),
                "\"unknown_key\": {\"nested\": [1, 2, {\"deep\": null}]}, ");
    const std::string path = WriteTemp("rules_unknown.json", body);
    std::string error;
    Check(yh::load_config(path, &error) != nullptr, "未知键被跳过而不报错");
  }
  {
    // \u 转义 + 代理对 → UTF-8
    std::string uni = kValid;
    uni.replace(uni.find("\"explorer.exe\""), std::string("\"explorer.exe\"").size(),
                "\"\\u4e2d\\u6587.exe\"");
    const std::string path = WriteTemp("rules_unicode.json", uni);
    std::string error;
    std::unique_ptr<yh::Config> config = yh::load_config(path, &error);
    Check(config != nullptr, "含 \\u 转义的样本能加载");
    if (config) {
      Check(config->process_allowlist[0] == "\xE4\xB8\xAD\xE6\x96\x87.exe",
            "\\u4e2d\\u6587 正确解成 UTF-8 中文");
    }
  }
  {
    std::string bad = kValid;
    bad.push_back('\xFF');  // 非法 UTF-8 字节
    const std::string path = WriteTemp("rules_badutf8.json", bad);
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "非法 UTF-8 拒绝加载");
  }
  {
    std::string bad = kValid;  // kValid 以 '\n}' 结尾（'）' 是 raw string 的终止符）
    bad += "}";                // '}' 之后再来一个 '}'
    const std::string path = WriteTemp("rules_trailing.json", bad);
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "'}' 之后有多余内容时拒绝加载");
  }
  {
    const std::string path =
        (SandboxDir() / "definitely_absent.json").string();
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "文件不存在拒绝加载");
    CheckNames(error, "无法打开", "文件不存在的 error 说明打不开");
  }
  {
    std::unique_ptr<yh::Config> config = yh::load_config(
        (SandboxDir() / "rules_valid.json").string(), nullptr);
    Check(config != nullptr, "error 传 nullptr 也能加载");
  }
  {
    // 中文目录：MSVC 的 ifstream(std::string) 按 ANSI 代码页解释路径，开不出来。
    // 但注意两处都得按 UTF-8 走，否则这条用例测的就不是它声称的那件事：
    //   1) path 从 const char* 构造时 MSVC 按 **ACP** 解释字节 —— 直接喂 UTF-8
    //      字节会把「中文目录」拼成 GBK 误解后的乱码目录名；
    //   2) path::string() 返回的也是 ACP，而 load_config 的契约是 **UTF-8**
    //      （见 config.cpp OpenRulesFile 的 CP_UTF8 转换）。
    // 所以目录名走 u8path()，交给 load_config 的走 u8string()。
    const std::string dir_name = "\xe4\xb8\xad\xe6\x96\x87\xe7\x9b\xae\xe5\xbd\x95";
    const std::filesystem::path dir = SandboxDir() / std::filesystem::u8path(dir_name);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    {
      std::ofstream out(dir / "rules.json", std::ios::binary);
      const std::string body = kValid;
      out.write(body.data(), static_cast<std::streamsize>(body.size()));
    }
    std::string error;
    Check(yh::load_config((dir / "rules.json").u8string(), &error) != nullptr,
          "中文目录下的配置文件能打开");
  }
}

// spec §8：service_interpreter_keywords 不得为空
void test_empty_interpreter_keywords_rejected() {
  {
    const std::string path =
        WriteTemp("rules_emptykw.json", WithValue("service_interpreter_keywords", "[]"));
    std::string error;
    Check(yh::load_config(path, &error) == nullptr, "service_interpreter_keywords 为空数组时拒绝加载");
    CheckNames(error, "service_interpreter_keywords",
               "空关键字数组的 error 指名 service_interpreter_keywords");
  }
}

// spec §2 硬约束 2：硬白名单下限在 C++ 里，配置改不动
void test_hard_allowlist_floor() {
  const std::vector<std::string> kFloor = {
      "swprv", "vmservice", "MicrosoftSoftware2ShadowCop4yProvider"};

  {
    const std::string path = WriteTemp("rules_nohard.json", WithValue("hard_allowlist", "[]"));
    std::string error;
    std::unique_ptr<yh::Config> config = yh::load_config(path, &error);
    Check(config != nullptr, "hard_allowlist 为空数组时仍能加载（下限兜底，不拒）");
    if (config) {
      for (const std::string& name : kFloor) {
        Check(yh::is_hard_allowlisted(name, config->hard_allowlist),
              "配置清空后 \"" + name + "\" 仍在硬白名单里");
      }
      Check(!yh::is_hard_allowlisted("vafdska", config->hard_allowlist),
            "vafdska 不在硬白名单里（不作 IOC）");
      Check(!yh::is_hard_allowlisted("MiniFilterDrv", config->hard_allowlist),
            "MiniFilterDrv 不在硬白名单里（不作 IOC）");
    }
  }
  {
    const std::string path = WriteTemp("rules_extra_hard.json",
                                       WithValue("hard_allowlist", "[\"AcmeUpdater\", \"swprv\"]"));
    std::string error;
    std::unique_ptr<yh::Config> config = yh::load_config(path, &error);
    Check(config != nullptr, "配置额外提供名单项时能加载");
    if (config) {
      Check(yh::is_hard_allowlisted("AcmeUpdater", config->hard_allowlist),
            "配置提供的额外项 AcmeUpdater 在名单里");
      for (const std::string& name : kFloor) {
        Check(yh::is_hard_allowlisted(name, config->hard_allowlist),
              "配置额外提供项后，\"" + name + "\" 仍在硬白名单里");
      }
      // 配置里重复写了 swprv，去重后应只出现一次
      int swprv_count = 0;
      for (const std::string& entry : config->hard_allowlist) {
        if (entry == "swprv") {
          ++swprv_count;
        }
      }
      Check(swprv_count == 1, "配置重复提供的 swprv 与下限去重后只出现一次");
    }
  }
}

}  // namespace

int main() {
  // 只清理本测试自己建的沙箱目录，不碰临时目录里的其它东西
  std::error_code ec;
  std::filesystem::remove_all(SandboxDir(), ec);
  std::filesystem::create_directories(SandboxDir(), ec);

  test_task3_required_cases();
  test_parser_branches();
  test_empty_interpreter_keywords_rejected();
  test_hard_allowlist_floor();

  std::filesystem::remove_all(SandboxDir(), ec);

  std::printf("%s：%d/%d 项通过\n", g_failures == 0 ? "全部通过" : "存在失败", g_checks - g_failures,
              g_checks);
  return g_failures == 0 ? 0 : 1;
}
