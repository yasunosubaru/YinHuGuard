// engine/src/internal.cpp
//
// internal.h 的实现。除 IsElevated 外全部是无副作用的纯工具，因此不需要
// 任何 Windows 系统状态，也就不必担心在测试里被误触。

#include "internal.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>

namespace yh {
namespace internal {

std::string ToLowerAscii(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return out;
}

bool IsSpace(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

std::wstring Utf8ToWide(const std::string& utf8) {
  if (utf8.empty()) {
    return std::wstring();
  }
  const int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                                          static_cast<int>(utf8.size()), nullptr, 0);
  if (needed <= 0) {
    return std::wstring();  // 非法 UTF-8
  }
  std::wstring wide(static_cast<size_t>(needed), L'\0');
  ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(),
                        static_cast<int>(utf8.size()), &wide[0], needed);
  return wide;
}

std::string WideToUtf8(const std::wstring& wide) {
  if (wide.empty()) {
    return std::string();
  }
  const int needed = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                          nullptr, 0, nullptr, nullptr);
  if (needed <= 0) {
    return std::string();
  }
  std::string utf8(static_cast<size_t>(needed), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), &utf8[0], needed,
                        nullptr, nullptr);
  return utf8;
}

char* DupUtf8(const std::string& s) {
  // +1 给结尾 NUL。malloc 而非 new[]：yh_string_free 用 free，两者必须配对。
  char* out = static_cast<char*>(std::malloc(s.size() + 1));
  if (out == nullptr) {
    return nullptr;
  }
  if (!s.empty()) {
    std::memcpy(out, s.data(), s.size());
  }
  out[s.size()] = '\0';
  return out;
}

namespace {

// 进程内最近一次错误。引擎是单实例桌面组件，不做跨线程并发扫描，
// 因此一个进程全局槽位足够；用 thread_local 是为了将来 Dart 侧把扫描
// 放进 isolate 时不会串台。
thread_local std::string g_last_error;

}  // namespace

void SetLastErrorText(const std::string& text) { g_last_error = text; }

const char* GetLastErrorText() { return g_last_error.c_str(); }

bool IsElevated() {
  HANDLE token = nullptr;
  if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return false;  // 拿不到就问不出来，按未提权处理——宁可少报权限，不可多报
  }
  TOKEN_ELEVATION elevation = {};
  DWORD returned = 0;
  const bool ok = ::GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation),
                                        &returned) != FALSE;
  ::CloseHandle(token);
  return ok && elevation.TokenIsElevated != 0;
}

bool AppendFinding(YhFindingList* list, const char* locator, const char* display_name,
                   const char* criteria, bool attributes_verified, bool hidden, bool system,
                   bool elevation_required, bool covered) {
  if (list == nullptr) {
    return false;
  }
  if (list->count == SIZE_MAX) {
    return false;  // 溢出防护，正常路径不可达
  }

  // 先把新数组建好再搬：搬之前任何一步失败，list 都还保持调用方能看到的一致状态。
  YhFinding* grown = static_cast<YhFinding*>(
      std::realloc(list->items, sizeof(YhFinding) * (list->count + 1)));
  if (grown == nullptr) {
    return false;
  }
  list->items = grown;

  YhFinding finding = {};
  finding.locator = DupUtf8(locator == nullptr ? "" : locator);
  finding.display_name = DupUtf8(display_name == nullptr ? "" : display_name);
  finding.criteria = DupUtf8(criteria == nullptr ? "" : criteria);
  if (finding.locator == nullptr || finding.display_name == nullptr || finding.criteria == nullptr) {
    // 三个串里某个没分配出来：释放这一个条目的全部三块，列表长度不变。
    std::free(finding.locator);
    std::free(finding.display_name);
    std::free(finding.criteria);
    return false;
  }
  finding.attributes_verified = attributes_verified ? 1 : 0;
  finding.hidden = hidden ? 1 : 0;
  finding.system = system ? 1 : 0;
  finding.elevation_required = elevation_required ? 1 : 0;
  finding.covered = covered ? 1 : 0;
  finding.timestamp = UnixSecondsNow();

  list->items[list->count] = finding;
  list->count += 1;
  return true;
}

void FreeFindingList(YhFindingList* list) {
  if (list == nullptr) {
    return;
  }
  for (size_t i = 0; i < list->count; ++i) {
    std::free(list->items[i].locator);
    std::free(list->items[i].display_name);
    std::free(list->items[i].criteria);
  }
  std::free(list->items);
  list->items = nullptr;
  list->count = 0;
}

double UnixSecondsNow() {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return std::chrono::duration<double>(now).count();
}

}  // namespace internal
}  // namespace yh
