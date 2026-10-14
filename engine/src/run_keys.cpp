// engine/src/run_keys.cpp
//
// 对应上游「扫描2/3：隐藏启动项」。三个键、引号提取回退链、H/S 属性判据
// 全部**忠实还原**；修掉的是上游一处真实漏报与本项目的一处要求：
//
//   上游漏报：上游拿到值后用 cmd 的 `if exist` 判断文件是否存在，而 cmd **不展开**
//   REG_EXPAND_SZ 里的 %VAR%。于是 `%TEMP%\x.exe` 这类启动项一律被判成「文件不存在」
//   而漏掉。这里先 expand_env_vars 再判存在。
//
//   未展开即未覆盖：expand_env_vars 回来 expanded_ok=false（变量查不到）时，
//   我们**无法判断文件是否存在**，此时必须产出 covered=0 的条目，不能当「不存在」跳过。
//   这是 Review Focus #2 的落点。
//
// 判据仍是上游那一条：文件存在 且 带 H 或 S 属性。

#include "internal.h"

#include <string>
#include <vector>

#include "yh_criteria.h"

namespace yh {
namespace internal {

namespace {

// 上游的三个键里有两条挂在 HKLM、一条挂在 HKCU，但 HKCU\SOFTWARE\WOW6432Node 不存在，
// 所以这里显式配 (root, subkey) 而不是靠键名推断。
struct RunKey {
  HKEY root;
  const wchar_t* subkey;
  const char* label;  // 报告里 locator 的前缀，用可读的根名
};

const RunKey kRunKeyList[] = {
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
     "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
     "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
     "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
};

// 读一个值；返回原始字节（REG_SZ / REG_EXPAND_SZ 的窄串按 ACP 存放，
// 交由 RegQueryValueExW + Wide 路径处理，见下）。取不到返回 false。
bool ReadValueRaw(HKEY key, const wchar_t* name, DWORD* type, std::vector<BYTE>* data) {
  DWORD size = 0;
  if (::RegQueryValueExW(key, name, nullptr, type, nullptr, &size) != ERROR_SUCCESS) {
    return false;
  }
  if (*type != REG_SZ && *type != REG_EXPAND_SZ) {
    return false;
  }
  data->assign(size, 0);
  if (size == 0) {
    return true;
  }
  if (::RegQueryValueExW(key, name, nullptr, type, data->data(), &size) != ERROR_SUCCESS) {
    return false;
  }
  data->resize(size);
  return true;
}

// REG_SZ 的数据是 UTF-16；转成 UTF-8 交给判据层（判据层只认 std::string UTF-8）。
std::string SzToUtf8(const std::vector<BYTE>& data) {
  if (data.size() < sizeof(wchar_t)) {
    return std::string();
  }
  const wchar_t* text = reinterpret_cast<const wchar_t*>(data.data());
  size_t chars = data.size() / sizeof(wchar_t);
  // 去掉结尾 NUL（注册表字符串通常带一个）
  while (chars > 0 && text[chars - 1] == L'\0') {
    --chars;
  }
  if (chars == 0) {
    return std::string();
  }
  return WideToUtf8(std::wstring(text, chars));
}

}  // namespace

int32_t ScanRunKeys(YhFindingList* findings) {
  for (const RunKey& run_key : kRunKeyList) {
    HKEY key = nullptr;
    const LSTATUS opened =
        ::RegOpenKeyExW(run_key.root, run_key.subkey, 0, KEY_READ, &key);
    if (opened != ERROR_SUCCESS) {
      // 某个键不存在（例如 WOW6432Node 在纯 64 位环境下缺席）是正常情况，
      // 不是错误；上游对打不开的键也是静默跳过。这里保持一致。
      continue;
    }

    for (DWORD index = 0;; ++index) {
      std::vector<wchar_t> name_buffer(512, L'\0');
      DWORD name_length = static_cast<DWORD>(name_buffer.size());
      const LSTATUS enumerated =
          ::RegEnumValueW(key, index, name_buffer.data(), &name_length, nullptr, nullptr, nullptr,
                          nullptr);
      if (enumerated == ERROR_NO_MORE_ITEMS) {
        break;
      }
      if (enumerated != ERROR_SUCCESS) {
        break;  // 读不动就停在这个键，不假装扫完了
      }

      DWORD type = 0;
      std::vector<BYTE> data;
      if (!ReadValueRaw(key, name_buffer.data(), &type, &data)) {
        continue;  // 非字符串类型的启动项不在上游判据范围内
      }

      const std::string value_name = WideToUtf8(std::wstring(name_buffer.data(), name_length));
      const std::string raw_data = SzToUtf8(data);
      if (raw_data.empty()) {
        continue;
      }

      // 上游三层回退：取引号内 → 取整串 → 剥尾随 ')'
      const std::string candidate = extract_run_value_path(raw_data);

      bool expanded_ok = false;
      const std::string expanded = expand_env_vars(candidate, &expanded_ok);

      const std::string locator = std::string(run_key.label) + "\\" + value_name;

      if (!expanded_ok) {
        // 变量查不到 → 判不了文件是否存在 → 记未覆盖。绝不跳过。
        if (!AppendFinding(findings, locator.c_str(), expanded.c_str(), "file_attr_hs",
                           /*attributes_verified=*/false, /*hidden=*/false, /*system=*/false,
                           /*elevation_required=*/false, /*covered=*/false)) {
          FreeFindingList(findings);
          SetLastErrorText("追加启动项发现时内存分配失败");
          return 2;
        }
        continue;
      }

      const std::wstring wide = Utf8ToWide(expanded);
      if (wide.empty()) {
        continue;  // 非法 UTF-8：判据层已无法处理，且这不是「未覆盖」而是数据本身坏了
      }
      const DWORD attrs = ::GetFileAttributesW(wide.c_str());
      if (attrs == INVALID_FILE_ATTRIBUTES) {
        // 上游 `if exist` 判据的等价物：文件不存在就不报。这是正常情况。
        continue;
      }
      if (!has_hidden_or_system(static_cast<uint32_t>(attrs))) {
        continue;
      }

      if (!AppendFinding(findings, locator.c_str(), expanded.c_str(), "file_attr_hs",
                         /*attributes_verified=*/true,
                         (attrs & FILE_ATTRIBUTE_HIDDEN) != 0,
                         (attrs & FILE_ATTRIBUTE_SYSTEM) != 0,
                         /*elevation_required=*/false, /*covered=*/true)) {
        FreeFindingList(findings);
        SetLastErrorText("追加启动项发现时内存分配失败");
        return 2;
      }
    }

    ::RegCloseKey(key);
  }
  return 0;
}

}  // namespace internal
}  // namespace yh
