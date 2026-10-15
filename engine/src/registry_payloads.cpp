// engine/src/registry_payloads.cpp
//
// 对应情报里的「注册表内存储载荷」。**不是启动项**，是银狐把 payload 与配置
// 藏进注册表的地方。它不产生启动效果，所以前面的三段扫描都碰不到它，
// 但它是清理时最容易被漏掉的一块 —— 只删了启动项而没删载荷，重启就回来了。
//
// 确认过的三处：`HKCU\Console\0`（Zscaler）、`HKCU\Console\1`（Atos，插件持久化）、
// `HKLM\SOFTWARE\IpDates_sun`（Cato CTRL）、`HKCU\SOFTWARE\Magisk`（Winos 加载器）。
// 外加一个标记串 `FaCai2024` —— loader 搜索它来定位配置区。
//
// 有个特殊的判别式：`HKCU\Console\<数字或哈希>` 下面那个值名本身是一串 32 位十六进制。
// 它不是文件名，没法写进 IOC 表，所以做成「值名形如 32 个十六进制字符」的启发式。

#include "internal.h"

#include <string>
#include <vector>

#include "ioc_table.h"
#include "yh_criteria.h"

namespace yh {
namespace internal {

namespace {

// 32 个十六进制字符 —— HKCU\Console\<key> 下那个 payload 值名的形状。
bool LooksLikePayloadValueName(const std::string& name) {
  if (name.size() != 32) {
    return false;
  }
  for (const char c : name) {
    const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                     (c >= 'A' && c <= 'F');
    if (!hex) {
      return false;
    }
  }
  return true;
}

bool ContainsIgnoreCase(const std::string& haystack, const std::string& needle) {
  return ToLowerAscii(haystack).find(ToLowerAscii(needle)) != std::string::npos;
}

struct RegistryProbe {
  HKEY root;
  const wchar_t* subkey;
  // 命中方式：按值名（32 位十六进制启发式、或 IOC 表里的值名）或按值数据（标记串）。
  bool match_hash_value_names;
  bool match_ioc_value_names;
  bool match_marker_in_value_data;
  const char* evidence_url;
  const char* note;
};

// 这些键是 Zscaler / Atos / Cato CTRL 明确记录过的，没有别的理由扩面。
const RegistryProbe kProbes[] = {
    // HKCU\Console\<PID 或 0/1>：值名是 32 位十六进制（或 0/1），值内容即载荷。
    {HKEY_CURRENT_USER, L"Console", /*match_hash_value_names=*/true,
     /*match_ioc_value_names=*/false,
     /*match_marker_in_value_data=*/true,
     "https://www.zscaler.com/de/blogs/security-research/technical-analysis-latest-variant-valleyrat",
     "值名是 32 位十六进制，值内容即最终 payload"},

    // IP 日期的键：`HKLM\SOFTWARE\IpDates_sun`，见 IOC 表。
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\IpDates_sun", false, true, false,
     ioc::kRegistryPayloadKeys[0].evidence_url, ioc::kRegistryPayloadKeys[0].note},
    {HKEY_LOCAL_MACHINE, L"SOFTWARE\\IpDatespecial", false, true, false,
     ioc::kRegistryPayloadKeys[1].evidence_url, ioc::kRegistryPayloadKeys[1].note},

    // Magisk：值 ring3_username 被写入当前用户名。
    {HKEY_CURRENT_USER, L"SOFTWARE\\Magisk", false, true, false,
     ioc::kRegistryPayloadKeys[2].evidence_url, ioc::kRegistryPayloadKeys[2].note},
};

// 读一个值的数据（字节），失败返回 false。
std::vector<BYTE> ReadValueData(HKEY key, const wchar_t* name) {
  DWORD size = 0;
  if (::RegQueryValueExW(key, name, nullptr, nullptr, nullptr, &size) != ERROR_SUCCESS) {
    return std::vector<BYTE>();
  }
  std::vector<BYTE> data(size, 0);
  if (size == 0) {
    return data;
  }
  if (::RegQueryValueExW(key, name, nullptr, nullptr, data.data(), &size) != ERROR_SUCCESS) {
    return std::vector<BYTE>();
  }
  data.resize(size);
  return data;
}

// 二进制数据里的子串搜索，大小写不敏感（仅 ASCII 段）。
bool DataContainsMarker(const std::vector<BYTE>& data, const std::string& marker) {
  if (data.empty() || marker.empty()) {
    return false;
  }
  const std::string lowered_marker = ToLowerAscii(marker);
  for (size_t i = 0; i + marker.size() <= data.size(); ++i) {
    bool hit = true;
    for (size_t j = 0; j < lowered_marker.size(); ++j) {
      char c = static_cast<char>(data[i + j]);
      if (c >= 'A' && c <= 'Z') {
        c = static_cast<char>(c - 'A' + 'a');
      }
      if (c != lowered_marker[j]) {
        hit = false;
        break;
      }
    }
    if (hit) {
      return true;
    }
  }
  return false;
}

// 沿着 IOC 表按值名匹配。命中返回 true 并把 evidence_url / note 一并带出来。
bool MatchIocValueName(const std::string& value_name, const char** evidence_url,
                       const char** note) {
  const std::string lowered = ToLowerAscii(value_name);
  for (const ioc::NameRule& rule : ioc::kRegistryPayloadKeys) {
    // IOC 表里存的是完整键路径，这里只取最后一段当值名比较。
    const std::string rule_path = ToLowerAscii(rule.name);
    const size_t last_sep = rule_path.find_last_of("\\/");
    const std::string rule_tail =
        last_sep == std::string::npos ? rule_path : rule_path.substr(last_sep + 1);
    if (rule_tail != lowered) {
      continue;
    }
    // `ipdates_sun` 这种「值名与键名相同」的也要能命中 —— 上面的 kProbes 已经
    // 把子键打开了，这里比的是值名。
    if (value_name.find('\\') == std::string::npos && rule_tail == lowered) {
      *evidence_url = rule.evidence_url;
      *note = rule.note;
      return true;
    }
  }
  // 键本身在 IOC 表里：这种情况下值是「整键存在的痕迹」而不是某个值名。
  for (const ioc::NameRule& rule : ioc::kRegistryPayloadKeys) {
    if (ToLowerAscii(rule.name).find(lowered) != std::string::npos ||
        lowered.find(ToLowerAscii(rule.name)) != std::string::npos) {
      *evidence_url = rule.evidence_url;
      *note = rule.note;
      return true;
    }
  }
  return false;
}

}  // namespace

int32_t ScanRegistryPayloads(YhFindingList* findings) {
  for (const RegistryProbe& probe : kProbes) {
    HKEY key = nullptr;
    const LSTATUS opened = ::RegOpenKeyExW(probe.root, probe.subkey, 0, KEY_READ, &key);
    if (opened != ERROR_SUCCESS) {
      continue;  // 键不存在是正常情况，不算未覆盖（本来就没有）
    }

    for (DWORD index = 0;; ++index) {
      std::vector<wchar_t> name_buffer(256, L'\0');
      DWORD name_length = static_cast<DWORD>(name_buffer.size());
      LSTATUS enumerated =
          ::RegEnumValueW(key, index, name_buffer.data(), &name_length, nullptr, nullptr,
                          nullptr, nullptr);
      if (enumerated == ERROR_NO_MORE_ITEMS) {
        break;
      }
      if (enumerated != ERROR_SUCCESS) {
        break;  // 读不动就停在这个键，不假装扫完了
      }

      const std::string value_name = WideToUtf8(std::wstring(name_buffer.data(), name_length));

      const char* evidence_url = probe.evidence_url;
      const char* note = probe.note;

      bool hit = false;
      if (probe.match_hash_value_names && LooksLikePayloadValueName(value_name)) {
        hit = true;
      }
      if (!hit && probe.match_ioc_value_names) {
        hit = MatchIocValueName(value_name, &evidence_url, &note);
      }
      if (!hit && probe.match_marker_in_value_data) {
        const std::vector<BYTE> data = ReadValueData(key, name_buffer.data());
        if (DataContainsMarker(data, ioc::kMarkerString)) {
          hit = true;
        }
      }

      if (!hit) {
        continue;
      }

      // locator 用完整键路径 + 值名，让报告里的东西能直接粘进删除命令。
      char narrow_subkey[512] = {};
      ::WideCharToMultiByte(CP_UTF8, 0, probe.subkey,
                            static_cast<int>(wcslen(probe.subkey)), narrow_subkey,
                            sizeof(narrow_subkey) - 1, nullptr, nullptr);
      const wchar_t* root_label = probe.root == HKEY_LOCAL_MACHINE ? L"HKLM" : L"HKCU";
      char narrow_root[16] = {};
      ::WideCharToMultiByte(CP_UTF8, 0, root_label, static_cast<int>(wcslen(root_label)),
                            narrow_root, sizeof(narrow_root) - 1, nullptr, nullptr);
      const std::string locator =
          std::string(narrow_root) + "\\" + narrow_subkey + "\\" + value_name;

      if (!AppendFinding(findings, locator.c_str(), value_name.c_str(), "name_match",
                         /*attributes_verified=*/false, /*hidden=*/false, /*system=*/false,
                         /*elevation_required=*/false, /*covered=*/true)) {
        ::RegCloseKey(key);
        FreeFindingList(findings);
        SetLastErrorText("追加注册表载荷发现时内存分配失败");
        return 2;
      }
    }

    ::RegCloseKey(key);
  }
  return 0;
}

}  // namespace internal
}  // namespace yh
