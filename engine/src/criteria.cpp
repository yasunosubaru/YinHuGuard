// engine/src/criteria.cpp
//
// 判据纯函数的实现。三个规则贯穿全文件：
//   1) 不静默降级——判不准就返回足够让调用方记 covered=0 的信息。
//   2) 上游语义优先，回退链逐条复刻，不做「看起来更合理」的改写。
//   3) 只读：不枚举、不写、不注册回调。

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <string>
#include <vector>

#include "yh_criteria.h"
#include "internal.h"

namespace yh {
namespace {

// 编码与小写转换统一实现在 internal.h / internal.cpp —— Task 3 的枚举文件也要用
// 同一套（严格模式 UTF-8，非法序列必须失败），各写一份会让 locator 的编码行为
// 在文件之间漂移，而 locator 是报告里唯一能把人带到文件的东西。
// 这里只做名字引入，不重复定义。
using internal::IsSpace;
using internal::ToLowerAscii;
using internal::Utf8ToWide;
using internal::WideToUtf8;

// 两段式调用 ExpandEnvironmentStringsW：先问长度再分配，不用固定大小缓冲。
// 环境变量表在两次调用之间被改动时按新长度重试，最多几次后放弃并交由调用方
// 记未覆盖——绝不返回半展开的结果冒充成功。
bool ExpandEnvironmentStrings(const std::wstring& in, std::wstring* out) {
  DWORD needed = ::ExpandEnvironmentStringsW(in.c_str(), nullptr, 0);
  if (needed == 0) {
    return false;
  }
  for (int attempt = 0; attempt < 4; ++attempt) {
    std::wstring buffer(static_cast<size_t>(needed) + 1, L'\0');
    const DWORD written = ::ExpandEnvironmentStringsW(
        in.c_str(), &buffer[0], static_cast<DWORD>(buffer.size()));
    if (written == 0) {
      return false;
    }
    if (written < buffer.size()) {
      // written 含结尾的 L'\0'，必须切掉——否则返回的路径尾部挂一个 NUL，
      // 后面 GetFileAttributesW 与 Dart 侧比较都会莫名其妙地对不上
      buffer.resize(static_cast<size_t>(written) - 1);
      *out = buffer;
      return true;
    }
    needed = written;  // 缓冲区不够，按新长度再来一次
  }
  return false;
}

// 词元的主干：去掉首尾引号 → 取最后一段路径分隔符之后的部分 → 取第一个 '.' 之前。
//   `C:\a\cmd.exe`     → `cmd`
//   `"C:\a\cmd.exe"`   → `cmd`   （服务 PathName 常带引号）
//   `mycmd.txt`        → `mycmd` （所以 mycmd.txt 不会命中关键字 cmd）
std::string StemOfToken(const std::string& token) {
  std::string stem = token;
  if (!stem.empty() && stem.front() == '"') {
    stem.erase(stem.begin());
  }
  if (!stem.empty() && stem.back() == '"') {
    stem.pop_back();
  }
  const size_t separator = stem.find_last_of("\\/");
  if (separator != std::string::npos) {
    stem = stem.substr(separator + 1);
  }
  const size_t dot = stem.find('.');
  if (dot != std::string::npos) {
    stem = stem.substr(0, dot);
  }
  return stem;
}

// 以 '/' 开头的关键字词（`/c`）必须整词元相等，否则 `/cleanup` 会命中 `/c`；
// 其余词必须等于某个词元的主干，否则 `mycmd.txt` 会命中 `cmd`。
bool WordMatchesToken(const std::string& word, const std::string& token) {
  if (!word.empty() && word.front() == '/') {
    return token == word;
  }
  return StemOfToken(token) == word;
}

// 在 lowered_image 的词元里从 start_offset 起找 word；命中时把 *next_offset 设到该词元
// 之后，使多词关键字保持先后顺序（`/c` 在前、`cmd.exe` 在后不算命中 `cmd /c`）。
// 空白集合与上面 IsSpace() 必须一致。
bool FindWordFrom(const std::string& lowered_image, const std::string& word,
                  size_t start_offset, size_t* next_offset) {
  size_t i = start_offset;
  while (i < lowered_image.size()) {
    const size_t end = lowered_image.find_first_of(" \t\r\n", i);
    const size_t stop = (end == std::string::npos) ? lowered_image.size() : end;
    if (WordMatchesToken(word, lowered_image.substr(i, stop - i))) {
      *next_offset = (end == std::string::npos) ? stop : end + 1;
      return true;
    }
    if (end == std::string::npos) {
      break;
    }
    i = end + 1;
  }
  return false;
}

// 一个关键字按空白切成若干词，逐词在目标串的词元里按顺序查找，全部命中才算命中。
// `cmd /c` 因此表示「cmd 这个可执行名在前、其后有独立的 /c 词元」，裸 `cmd.exe` 不算——
// spec §4.3 的 service_interpreter 要的就是这个，而上游 findstr 会误命中。
bool KeywordMatches(const std::string& lowered_image, const std::string& keyword) {
  size_t scanned = 0;
  size_t matched_words = 0;
  size_t search_from = 0;
  while (scanned < keyword.size()) {
    while (scanned < keyword.size() && IsSpace(keyword[scanned])) {
      ++scanned;
    }
    if (scanned >= keyword.size()) {
      break;
    }
    const size_t word_begin = scanned;
    while (scanned < keyword.size() && !IsSpace(keyword[scanned])) {
      ++scanned;
    }
    // 关键字来自 rules.json，用户完全可能写成 "PowerShell" 或 "CMD /C"。
    // 不转小写会让整条 service_interpreter 判据静默失效，而头文件承诺的是大小写不敏感。
    const std::string word = ToLowerAscii(keyword.substr(word_begin, scanned - word_begin));
    size_t next_offset = 0;
    if (!FindWordFrom(lowered_image, word, search_from, &next_offset)) {
      return false;
    }
    search_from = next_offset;
    ++matched_words;
  }
  // 空串或纯空白的关键字不构成命中条件——配置被清空时绝不能变成「全部命中」
  return matched_words > 0;
}

}  // namespace

bool has_hidden_or_system(uint32_t file_attributes) {
  // FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
  return (file_attributes & (0x2u | 0x4u)) != 0u;
}

std::string extract_run_value_path(const std::string& reg_value_data) {
  // 上游三层回退。')' 噪声有两个可能位置：整串末尾，或引号内容末尾，
  // 所以要剥两次——只剥一次的话 `C:\a\b.exe")` 与 `"C:\a\b.exe)"` 会各错一半。
  std::string value = reg_value_data;

  // 第一层：剥整串末尾的 ')'（上游 reg query 输出的噪声残留）
  if (!value.empty() && value.back() == ')') {
    value.pop_back();
  }

  // 第二层：取首个 '"' 到末个 '"' 之间的内容；引号内取不到就保留整串
  const size_t first_quote = value.find('"');
  if (first_quote != std::string::npos) {
    const size_t last_quote = value.rfind('"');
    if (last_quote > first_quote) {
      value = value.substr(first_quote + 1, last_quote - first_quote - 1);
    }
  }

  // 第二层之后再来一次：引号内容末尾也可能带 ')'
  if (!value.empty() && value.back() == ')') {
    value.pop_back();
  }

  // 第三层：剥掉残留的孤立引号（无引号、或只有一侧引号的畸形值）
  if (!value.empty() && value.front() == '"') {
    value.erase(value.begin());
  }
  if (!value.empty() && value.back() == '"') {
    value.pop_back();
  }
  return value;
}

std::string expand_env_vars(const std::string& path, bool* expanded_ok) {
  // 先自己探一遍未知变量：ExpandEnvironmentStringsW 对未定义变量是原样保留，
  // 只看返回值无法区分「已完全展开」和「还带着 %VAR%」。
  // 调用方据此决定记 covered=0 还是照常判定（spec §4.2 的上游漏报修复）。
  bool all_known = true;
  size_t percent = path.find('%');
  while (percent != std::string::npos) {
    const size_t close = path.find('%', percent + 1);
    if (close == std::string::npos) {
      break;  // 落单的 '%'，不是变量引用
    }
    const std::string name = path.substr(percent + 1, close - percent - 1);
    if (!name.empty()) {
      const std::wstring wide_name = Utf8ToWide(name);
      if (wide_name.empty()) {
        all_known = false;
      } else {
        // 返回 0 且 ERROR_ENVVAR_NOT_FOUND 才是「不存在」；
        // 变量存在但取值为空不算未知。
        ::SetLastError(ERROR_SUCCESS);
        ::GetEnvironmentVariableW(wide_name.c_str(), nullptr, 0);
        if (::GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
          all_known = false;
        }
      }
    }
    percent = path.find('%', close + 1);
  }
  if (expanded_ok) {
    *expanded_ok = all_known;
  }

  if (path.empty()) {
    return path;
  }
  const std::wstring wide_path = Utf8ToWide(path);
  if (wide_path.empty()) {
    if (expanded_ok) {
      *expanded_ok = false;  // 不是合法 UTF-8，原样交回，调用方记未覆盖
    }
    return path;
  }
  std::wstring expanded;
  if (!ExpandEnvironmentStrings(wide_path, &expanded)) {
    if (expanded_ok) {
      *expanded_ok = false;
    }
    return path;
  }
  return WideToUtf8(expanded);
}

std::string strip_quotes_and_args(const std::string& image_path) {
  if (image_path.empty()) {
    return image_path;
  }
  if (image_path.front() == '"') {
    const size_t close_quote = image_path.find('"', 1);
    if (close_quote != std::string::npos) {
      return image_path.substr(1, close_quote - 1);  // 闭合引号之后全丢
    }
    return image_path.substr(1);  // 只有起始引号：畸形值，保留其余全部
  }
  const size_t first_space = image_path.find(' ');
  if (first_space == std::string::npos) {
    return image_path;
  }
  return image_path.substr(0, first_space);
}

bool matches_interpreter(const std::string& image_path,
                         const std::vector<std::string>& keywords) {
  if (image_path.empty()) {
    return false;
  }
  // 不先剥参数：上游就是对整行 ImagePath 做 findstr，
  // `"C:\a\cmd.exe" /c x.bat` 这类必须照样命中。
  const std::string lowered_image = ToLowerAscii(image_path);
  for (const std::string& keyword : keywords) {
    if (KeywordMatches(lowered_image, keyword)) {
      return true;
    }
  }
  return false;
}

bool path_in_prefixes(const std::string& image_path,
                      const std::vector<std::string>& prefixes) {
  // 服务 PathName 常带引号和参数（"C:\...exe" -k netsvcs），先剥干净再判前缀，
  // 否则每个带参数的系统服务都会被 service_path_heuristic 误报。
  const std::string lowered_path = ToLowerAscii(strip_quotes_and_args(image_path));
  if (lowered_path.empty()) {
    return false;
  }
  for (const std::string& raw_prefix : prefixes) {
    std::string prefix = raw_prefix;
    // 手工抄进配置的尾随分隔符（"C:\Windows\System32\"）会让边界判定落在字母上，
    // 等于悄悄关掉整条前缀——先去掉。
    while (!prefix.empty() && (prefix.back() == '\\' || prefix.back() == '/')) {
      prefix.pop_back();
    }
    if (prefix.empty()) {
      continue;
    }
    const std::string lowered_prefix = ToLowerAscii(prefix);
    // 边界字符必须存在，因此「恰好等于前缀」不算在内
    if (lowered_path.size() <= lowered_prefix.size()) {
      continue;
    }
    if (lowered_path.compare(0, lowered_prefix.size(), lowered_prefix) != 0) {
      continue;
    }
    const char boundary = lowered_path[lowered_prefix.size()];
    if (boundary == '\\' || boundary == '/') {
      return true;
    }
  }
  return false;
}

bool is_hard_allowlisted(const std::string& name,
                         const std::vector<std::string>& hard_allowlist) {
  if (name.empty()) {
    return false;  // 空名字不该被空表项命中
  }
  const std::string lowered_name = ToLowerAscii(name);
  for (const std::string& entry : hard_allowlist) {
    if (ToLowerAscii(entry) == lowered_name) {
      return true;
    }
  }
  return false;
}

}  // namespace yh
