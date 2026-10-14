// engine/src/config.cpp
//
// rules.json 的读取与校验。刻意不引入 JSON 库（选型是架构决定，不是本文件的自由度）：
// rules.json 是扁平形状——顶层对象的键固定，值只有整数、字符串、字符串数组三种，
// 所以这里用一个约两百行的专用读取器，换来零依赖、零供应链面积。
//
// 能做的形状就做，做不了的形状一律报错并指名键名，绝不猜、绝不跳过：
//   * 未知键照常跳过（JSON 惯例，向后兼容）；必需键缺失则明确报错——
//     把 "hard_allowlistt" 手抄错成另一个名字，会在必需键检查里暴露出来。
//   * 重复键直接拒绝，否则后写的会悄悄覆盖前一份名单。
//   * 键内任一项不是字符串即拒绝该键。
//   * 非法 UTF-8 直接拒绝，绝不返回带替换字符的路径——那会让报告里的
//     locator 变成看似正常的乱码。
//   * 文件开头的 UTF-8 BOM 跳过（Windows 编辑器默认会写）。
//
// 另外两条来自 spec 的硬约束，在此落地而不是交给调用方自觉：
//   * service_interpreter_keywords 为空即拒绝（spec §8）——否则整条判据静默失效。
//   * 硬白名单下限 swprv / vmservice / MicrosoftSoftware2ShadowCop4yProvider 与配置
//     取并集（spec §2 硬约束 2）——配置改不动这三个名字。

#include "yh_engine.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <vector>

namespace yh {
namespace {

const int kSupportedSchemaVersion = 1;
const size_t kMinAllowPrefixes = 2;  // spec §8：service_path_allow_prefixes 至少两项

// spec §8：service_interpreter_keywords 至少一项。
// 空数组合法的话，整条 service_interpreter 判据会静默失效。
const size_t kMinInterpreterKeywords = 1;

// 硬白名单下限（spec §2 硬约束 2）：这三个名字恒在名单里，与 rules.json 提供的
// 同名项取并集。配置改不动它们——把 hard_allowlist 清空，swprv 依然不可报。
// vafdska / MiniFilterDrv 不在其中：情报未找到任何银狐出处，不作 IOC（spec §4.5）。
const char* const kHardAllowlistFloor[] = {
    "swprv",
    "vmservice",
    "MicrosoftSoftware2ShadowCop4yProvider",
};

// 与 criteria.cpp 同名的判定，各自文件内私有，就地复制一行比抽公共头更划算
bool IsSpace(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

void SetError(std::string* error, const std::string& message) {
  if (error) {
    *error = message;
  }
}

// 大小写不敏感全等（ASCII），与 criteria.cpp 的 ToLowerAscii 同一套规则
bool EqualsIgnoreCaseAscii(const std::string& left, const char* right) {
  size_t i = 0;
  for (; i < left.size(); ++i) {
    if (right[i] == '\0') {
      return false;
    }
    const char a = (left[i] >= 'A' && left[i] <= 'Z')
                       ? static_cast<char>(left[i] - 'A' + 'a')
                       : left[i];
    const char b = (right[i] >= 'A' && right[i] <= 'Z')
                       ? static_cast<char>(right[i] - 'A' + 'a')
                       : right[i];
    if (a != b) {
      return false;
    }
  }
  return right[i] == '\0';
}

// 把硬白名单下限并进配置给的名单（大小写不敏感去重）。就地改写 out。
void ApplyHardAllowlistFloor(std::vector<std::string>* out) {
  for (const char* floor_entry : kHardAllowlistFloor) {
    bool present = false;
    for (const std::string& entry : *out) {
      if (EqualsIgnoreCaseAscii(entry, floor_entry)) {
        present = true;
        break;
      }
    }
    if (!present) {
      out->push_back(floor_entry);
    }
  }
}

// 严格 UTF-8 校验：拒绝过长编码、越界码点、代理项与截断序列。
// 与 criteria.cpp 的宽窄转换同源原则——非法输入宁可拒绝加载，
// 也不让带 U+FFFD 的路径混进报告冒充正常 locator。
bool ValidateUtf8(const std::string& text) {
  size_t i = 0;
  while (i < text.size()) {
    const unsigned char lead = static_cast<unsigned char>(text[i]);
    size_t extra = 0;
    unsigned code_point = 0;
    if (lead < 0x80u) {
      ++i;
      continue;
    } else if ((lead & 0xE0u) == 0xC0u) {
      extra = 1;
      code_point = lead & 0x1Fu;
    } else if ((lead & 0xF0u) == 0xE0u) {
      extra = 2;
      code_point = lead & 0x0Fu;
    } else if ((lead & 0xF8u) == 0xF0u) {
      extra = 3;
      code_point = lead & 0x07u;
    } else {
      return false;  // 续接字节或 5 字节以上的非法首字节
    }
    if (i + extra >= text.size()) {
      return false;
    }
    for (size_t k = 1; k <= extra; ++k) {
      const unsigned char continuation = static_cast<unsigned char>(text[i + k]);
      if ((continuation & 0xC0u) != 0x80u) {
        return false;
      }
      code_point = (code_point << 6) | (continuation & 0x3Fu);
    }
    if (extra == 1 && code_point < 0x80u) {
      return false;
    }
    if (extra == 2 && code_point < 0x800u) {
      return false;
    }
    if (extra == 3 && code_point < 0x10000u) {
      return false;
    }
    if (code_point > 0x10FFFFu || (code_point >= 0xD800u && code_point <= 0xDFFFu)) {
      return false;
    }
    i += extra + 1;
  }
  return true;
}

// 专用 JSON 读取器。只实现上面三种值形状 + 未知键跳过所需的通用扫描。
struct Parser {
  const std::string& text;
  size_t pos = 0;
  std::string error;  // 只记录首个失败原因

  // pos 所在位置的行列（1 起），让语法错误能被用户直接定位
  std::string Where() const {
    size_t line = 1;
    size_t column = 1;
    for (size_t i = 0; i < pos && i < text.size(); ++i) {
      if (text[i] == '\n') {
        ++line;
        column = 1;
      } else {
        ++column;
      }
    }
    return "第 " + std::to_string(line) + " 行第 " + std::to_string(column) + " 列";
  }

  void SkipSpace() {
    while (pos < text.size() && IsSpace(text[pos])) {
      ++pos;
    }
  }

  bool Fail(const std::string& message) {
    if (error.empty()) {
      error = "rules.json 语法错误（" + Where() + "）：" + message;
    }
    return false;
  }

  bool Expect(char expected) {
    SkipSpace();
    if (pos >= text.size() || text[pos] != expected) {
      return Fail(std::string("期望 '") + expected + "'");
    }
    ++pos;
    return true;
  }

  bool AtEnd() {
    SkipSpace();
    return pos >= text.size();
  }

  bool Peek(char expected) {
    SkipSpace();
    return pos < text.size() && text[pos] == expected;
  }

  void AppendUtf8(unsigned code_point, std::string* out);

  bool ParseHex4(unsigned* out);
  bool ParseString(std::string* out);
  bool ParseInt(int* out);
  bool ParseStringArray(std::vector<std::string>* out);
  bool SkipValue();
};

void Parser::AppendUtf8(unsigned code_point, std::string* out) {
  if (code_point < 0x80u) {
    out->push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800u) {
    out->push_back(static_cast<char>(0xC0u | (code_point >> 6)));
    out->push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  } else if (code_point < 0x10000u) {
    out->push_back(static_cast<char>(0xE0u | (code_point >> 12)));
    out->push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
    out->push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  } else {
    out->push_back(static_cast<char>(0xF0u | (code_point >> 18)));
    out->push_back(static_cast<char>(0x80u | ((code_point >> 12) & 0x3Fu)));
    out->push_back(static_cast<char>(0x80u | ((code_point >> 6) & 0x3Fu)));
    out->push_back(static_cast<char>(0x80u | (code_point & 0x3Fu)));
  }
}

bool Parser::ParseHex4(unsigned* out) {
  if (pos + 4 > text.size()) {
    return Fail("\\u 转义不足四位");
  }
  unsigned value = 0;
  for (int i = 0; i < 4; ++i) {
    const char c = text[pos + static_cast<size_t>(i)];
    value <<= 4;
    if (c >= '0' && c <= '9') {
      value |= static_cast<unsigned>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      value |= static_cast<unsigned>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      value |= static_cast<unsigned>(c - 'A' + 10);
    } else {
      return Fail("\\u 转义里有非十六进制字符");
    }
  }
  pos += 4;
  *out = value;
  return true;
}

bool Parser::ParseString(std::string* out) {
  out->clear();
  if (!Expect('"')) {
    return false;
  }
  for (;;) {
    if (pos >= text.size()) {
      return Fail("字符串没有闭合引号");
    }
    const char c = text[pos];
    if (c == '"') {
      ++pos;
      return true;
    }
    if (static_cast<unsigned char>(c) < 0x20) {
      return Fail("字符串里有未转义的控制字符");
    }
    if (c != '\\') {
      out->push_back(c);
      ++pos;
      continue;
    }
    ++pos;
    if (pos >= text.size()) {
      return Fail("转义符之后内容被截断");
    }
    const char escaped = text[pos++];
    switch (escaped) {
      case '"': out->push_back('"'); break;
      case '\\': out->push_back('\\'); break;
      case '/': out->push_back('/'); break;
      case 'b': out->push_back('\b'); break;
      case 'f': out->push_back('\f'); break;
      case 'n': out->push_back('\n'); break;
      case 'r': out->push_back('\r'); break;
      case 't': out->push_back('\t'); break;
      case 'u': {
        unsigned code_point = 0;
        if (!ParseHex4(&code_point)) {
          return false;
        }
        if (code_point >= 0xD800u && code_point <= 0xDBFFu) {
          // 高位代理必须配一个低位代理，否则是不完整的 UTF-16
          if (pos + 1 >= text.size() || text[pos] != '\\' || text[pos + 1] != 'u') {
            return Fail("孤立的高位代理");
          }
          pos += 2;
          unsigned low = 0;
          if (!ParseHex4(&low)) {
            return false;
          }
          if (low < 0xDC00u || low > 0xDFFFu) {
            return Fail("高位代理之后跟的不是低位代理");
          }
          code_point = 0x10000u + ((code_point - 0xD800u) << 10) + (low - 0xDC00u);
        } else if (code_point >= 0xDC00u && code_point <= 0xDFFFu) {
          return Fail("孤立的低位代理");
        }
        AppendUtf8(code_point, out);
        break;
      }
      default:
        return Fail("不支持的转义 \\" + std::string(1, escaped));
    }
  }
}

bool Parser::ParseInt(int* out) {
  SkipSpace();
  const size_t begin = pos;
  while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
    ++pos;
  }
  if (pos == begin) {
    return Fail("期望整数");
  }
  if (pos - begin > 9) {
    return Fail("整数超出可表示范围");
  }
  int value = 0;
  for (size_t i = begin; i < pos; ++i) {
    value = value * 10 + (text[i] - '0');
  }
  *out = value;
  return true;
}

bool Parser::ParseStringArray(std::vector<std::string>* out) {
  out->clear();
  if (!Expect('[')) {
    return false;
  }
  if (Peek(']')) {
    ++pos;  // 空数组合法
    return true;
  }
  for (;;) {
    std::string item;
    if (!ParseString(&item)) {
      return false;
    }
    out->push_back(std::move(item));
    if (Peek(',')) {
      ++pos;
      continue;
    }
    if (Peek(']')) {
      ++pos;
      return true;
    }
    return Fail("字符串数组里期望 ',' 或 ']'");
  }
}

// 跳过任意合法 JSON 值，只为消费掉未知键的内容——形状不参与校验，但语法必须合法
bool Parser::SkipValue() {
  SkipSpace();
  if (pos >= text.size()) {
    return Fail("值缺失");
  }
  const char head = text[pos];
  if (head == '"') {
    std::string ignored;
    return ParseString(&ignored);
  }
  if (head == '{' || head == '[') {
    const char close = (head == '{') ? '}' : ']';
    ++pos;
    for (;;) {
      SkipSpace();
      if (pos >= text.size()) {
        return Fail("括号没有闭合");
      }
      if (text[pos] == close) {
        ++pos;
        return true;
      }
      if (!SkipValue()) {
        return false;
      }
      SkipSpace();
      if (pos < text.size() && text[pos] == ',') {
        ++pos;
        continue;
      }
      if (pos < text.size() && text[pos] == ':') {
        ++pos;
        continue;  // 对象里的键名分隔符
      }
      if (pos < text.size() && text[pos] == close) {
        ++pos;
        return true;
      }
      return Fail("括号内期望 ',' ':' 或闭合括号");
    }
  }
  const size_t begin = pos;
  while (pos < text.size() && !IsSpace(text[pos]) && text[pos] != ',' && text[pos] != '}' &&
         text[pos] != ']') {
    ++pos;
  }
  if (pos == begin) {
    return Fail("无法识别的值");
  }
  return true;  // 数字 / true / false / null
}

// MSVC 的 std::ifstream(const std::string&) 按 **ANSI 代码页** 解释路径，
// 中文目录（例如 D:\下载\YinHuGuard\rules.json）会直接打不开，最终报成
// 「无法打开配置文件」——一个看着像配置坏了、实际是路径编码错的假象。
// plan 的 Review Focus #3 正是中文路径，这里显式走 UTF-8 → UTF-16。
// 返回默认构造的 ifstream 即代表打不开，交给调用方走同一条错误分支。
std::ifstream OpenRulesFile(const std::string& utf8_path) {
  if (utf8_path.empty()) {
    return std::ifstream();
  }
  const int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_path.data(),
                                           static_cast<int>(utf8_path.size()), nullptr, 0);
  if (needed <= 0) {
    return std::ifstream();
  }
  std::wstring wide_path(static_cast<size_t>(needed), L'\0');
  ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8_path.data(),
                        static_cast<int>(utf8_path.size()), &wide_path[0], needed);
  return std::ifstream(wide_path, std::ios::binary);
}

}  // namespace

std::unique_ptr<Config> load_config(const std::string& path, std::string* error) {
  if (error) {
    error->clear();
  }
  std::ifstream file = OpenRulesFile(path);
  if (!file) {
    SetError(error, "无法打开配置文件：" + path);
    return nullptr;
  }
  std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  if (file.bad()) {
    SetError(error, "读取配置文件失败：" + path);
    return nullptr;
  }
  if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEFu &&
      static_cast<unsigned char>(text[1]) == 0xBBu && static_cast<unsigned char>(text[2]) == 0xBFu) {
    text.erase(0, 3);
  }
  if (!ValidateUtf8(text)) {
    SetError(error, "配置文件不是合法 UTF-8：" + path);
    return nullptr;
  }

  Parser parser{text};
  std::unique_ptr<Config> config(new Config());
  std::set<std::string> seen_keys;

  if (!parser.Expect('{')) {
    SetError(error, parser.error);
    return nullptr;
  }
  if (parser.Peek('}')) {
    SetError(error, "rules.json 是空对象，必需键 \"schema_version\" 缺失");
    return nullptr;
  }

  // 取值后统一判必需键，避免「第一个缺失的键」随书写顺序漂移
  bool schema_version_seen = false;
  bool keywords_seen = false;
  bool prefixes_seen = false;
  bool process_allowlist_seen = false;
  bool hard_allowlist_seen = false;
  bool system_process_names_seen = false;

  for (;;) {
    std::string key;
    if (!parser.ParseString(&key)) {
      SetError(error, "rules.json 的键名不合法：" + parser.error);
      return nullptr;
    }
    if (!seen_keys.insert(key).second) {
      SetError(error, "rules.json 里的键 \"" + key + "\" 重复出现，后一份会覆盖前一份");
      return nullptr;
    }
    if (!parser.Expect(':')) {
      SetError(error, "键 \"" + key + "\" 之后缺少 ':'");
      return nullptr;
    }

    if (key == "schema_version") {
      int version = 0;
      if (!parser.ParseInt(&version)) {
        SetError(error, "键 \"schema_version\" 的值不合法：" + parser.error);
        return nullptr;
      }
      if (version != kSupportedSchemaVersion) {
        SetError(error, "键 \"schema_version\" 的值是 " + std::to_string(version) +
                            "，本程序只支持 " + std::to_string(kSupportedSchemaVersion));
        return nullptr;
      }
      config->schema_version = version;
      schema_version_seen = true;
    } else if (key == "updated_at") {
      if (!parser.ParseString(&config->updated_at)) {
        SetError(error, "键 \"updated_at\" 的值不合法：" + parser.error);
        return nullptr;
      }
    } else if (key == "service_interpreter_keywords") {
      if (!parser.ParseStringArray(&config->service_interpreter_keywords)) {
        SetError(error, "键 \"service_interpreter_keywords\" 必须是字符串数组：" + parser.error);
        return nullptr;
      }
      keywords_seen = true;
    } else if (key == "service_path_allow_prefixes") {
      if (!parser.ParseStringArray(&config->service_path_allow_prefixes)) {
        SetError(error, "键 \"service_path_allow_prefixes\" 必须是字符串数组：" + parser.error);
        return nullptr;
      }
      prefixes_seen = true;
    } else if (key == "process_allowlist") {
      if (!parser.ParseStringArray(&config->process_allowlist)) {
        SetError(error, "键 \"process_allowlist\" 必须是字符串数组：" + parser.error);
        return nullptr;
      }
      process_allowlist_seen = true;
    } else if (key == "hard_allowlist") {
      if (!parser.ParseStringArray(&config->hard_allowlist)) {
        SetError(error, "键 \"hard_allowlist\" 必须是字符串数组：" + parser.error);
        return nullptr;
      }
      hard_allowlist_seen = true;
    } else if (key == "system_process_names") {
      if (!parser.ParseStringArray(&config->system_process_names)) {
        SetError(error, "键 \"system_process_names\" 必须是字符串数组：" + parser.error);
        return nullptr;
      }
      system_process_names_seen = true;
    } else {
      if (!parser.SkipValue()) {
        SetError(error, "键 \"" + key + "\" 的值不合法：" + parser.error);
        return nullptr;
      }
    }

    if (parser.Peek(',')) {
      ++parser.pos;
      continue;
    }
    if (parser.Peek('}')) {
      ++parser.pos;
      break;
    }
    SetError(error, "键 \"" + key + "\" 之后缺少 ',' 或 '}'");
    return nullptr;
  }

  if (!parser.AtEnd()) {
    SetError(error, "rules.json 的 '}' 之后还有多余内容（" + parser.Where() + "）");
    return nullptr;
  }

  if (!schema_version_seen) {
    SetError(error, "rules.json 缺少必需键 \"schema_version\"");
    return nullptr;
  }
  struct RequiredArray {
    const char* key;
    bool seen;
  };
  const RequiredArray required_arrays[] = {
      {"service_interpreter_keywords", keywords_seen},
      {"service_path_allow_prefixes", prefixes_seen},
      {"process_allowlist", process_allowlist_seen},
      {"hard_allowlist", hard_allowlist_seen},
      {"system_process_names", system_process_names_seen},
  };
  for (const RequiredArray& required : required_arrays) {
    if (!required.seen) {
      SetError(error, std::string("rules.json 缺少必需键 \"") + required.key + "\"");
      return nullptr;
    }
  }
  if (config->service_path_allow_prefixes.size() < kMinAllowPrefixes) {
    SetError(error, "键 \"service_path_allow_prefixes\" 只有 " +
                        std::to_string(config->service_path_allow_prefixes.size()) +
                        " 项，spec §8 要求至少 " + std::to_string(kMinAllowPrefixes) + " 项");
    return nullptr;
  }
  if (config->service_interpreter_keywords.size() < kMinInterpreterKeywords) {
    SetError(error, "键 \"service_interpreter_keywords\" 是空数组，spec §8 要求至少 " +
                        std::to_string(kMinInterpreterKeywords) +
                        " 项——清空它会让 service_interpreter 判据整体失效");
    return nullptr;
  }
  // 硬白名单下限在此并入，之后的调用方只认 config->hard_allowlist 一份名单
  ApplyHardAllowlistFloor(&config->hard_allowlist);
  return config;
}

}  // namespace yh
