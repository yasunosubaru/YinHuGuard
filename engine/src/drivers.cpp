// engine/src/drivers.cpp
//
// 驱动服务。这一条是**补一期漏掉的最要紧的一类**。
//
// 为什么单独扫：银狐杀不掉进程的办法是驱动。BYOVD 全家（amsdk.sys / wamsdk.sys /
// BootRepair.sys …）全都有合法证书签名，所以「进程代码签名校验」挡不住它们，
// 只能靠已知的文件名认。它们的共同目的只有一个：把 PID 送进内核调
// ZwTerminateProcess，杀用户态杀不掉的进程。
//
// 判据两条：
//   name_match       —— 驱动名或驱动文件的主干名命中 IOC 表
//   path_heuristic   —— ImagePath 不在 System32\drivers 或 SysWOW64\drivers 里
//                        （正常驱动都装在那儿，跑别处的驱动本身就是信号）
//
// 枚举走 SERVICE_DRIVER 而不是从 Win32 服务里挑 —— 驱动在 SCM 里是独立的
// 服务类型，只枚举 SERVICE_WIN32 会整类漏掉。

#include "internal.h"

#include <string>
#include <vector>

#include "ioc_table.h"
#include "service_enum.h"
#include "yh_criteria.h"

namespace yh {
namespace internal {

namespace {

// 驱动该在的两个目录。其它地方出现的驱动都是疑点。
const wchar_t* const kDriverDirs[] = {
    L"c:\\windows\\system32\\drivers",
    L"c:\\windows\\syswow64\\drivers",
    L"c:\\windows\\system32\\driverstore\\repository",
};

// 主干名：最后一段路径、去掉扩展名。amsdk.sys -> amsdk。
std::string StemOfPath(const std::string& path) {
  size_t cut = path.find_last_of("\\/");
  const std::string name = cut == std::string::npos ? path : path.substr(cut + 1);
  cut = name.find_last_of('.');
  return cut == std::string::npos ? name : name.substr(0, cut);
}

std::string LowerWideToUtf8(const std::wstring& wide) {
  return ToLowerAscii(WideToUtf8(wide));
}

// ImagePath 在两段式缓冲里取到（见 service_enum.cpp）。
std::wstring QueryConfigPath(SC_HANDLE service) {
  DWORD needed = 0;
  ::QueryServiceConfigW(service, nullptr, 0, &needed);
  if (needed == 0) {
    return std::wstring();
  }
  std::vector<BYTE> buffer(needed, 0);
  QUERY_SERVICE_CONFIGW* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
  if (!::QueryServiceConfigW(service, config, needed, &needed)) {
    return std::wstring();
  }
  if (config->lpBinaryPathName == nullptr) {
    return std::wstring();
  }
  return std::wstring(config->lpBinaryPathName);
}

// 命中的那份 IOC，用于带上出处。找不到返回 nullptr。
const ioc::NameRule* DriverNameRule(const std::string& stem) {
  const std::string lowered = ToLowerAscii(stem);
  for (const ioc::NameRule& rule : ioc::kDriverNames) {
    if (lowered == ToLowerAscii(rule.name)) {
      return &rule;
    }
  }
  return nullptr;
}

}  // namespace

int32_t ScanDrivers(YhFindingList* findings, const ServiceScanOptions& options) {
  SC_HANDLE manager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT |
                                                             SC_MANAGER_ENUMERATE_SERVICE);
  if (manager == nullptr) {
    // 这里不能当成「这台机器没有驱动」——那是枚举本身失败了。
    if (findings != nullptr) {
      if (!AppendFinding(findings, "", "", "path_heuristic", false, false, false,
                         /*elevation_required=*/false, /*covered=*/false)) {
        return 2;
      }
    }
    return 2;
  }

  std::vector<BYTE> buffer;
  DWORD returned = 0;
  if (!EnumerateServicesRaw(manager, SERVICE_DRIVER, &buffer, &returned)) {
    ::CloseServiceHandle(manager);
    if (findings != nullptr) {
      if (!AppendFinding(findings, "", "", "path_heuristic", false, false, false,
                         /*elevation_required=*/false, /*covered=*/false)) {
        return 2;
      }
    }
    return 2;
  }

  const ENUM_SERVICE_STATUS_PROCESSW* entries =
      reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

  for (DWORD i = 0; i < returned; ++i) {
    const std::string service_name = WideToUtf8(entries[i].lpServiceName);
    const std::string display_name = WideToUtf8(entries[i].lpDisplayName);

    SC_HANDLE service = ::OpenServiceW(
        manager, entries[i].lpServiceName,
        SC_MANAGER_CONNECT | SERVICE_QUERY_CONFIG);
    if (service == nullptr) {
      const bool denied = (::GetLastError() == ERROR_ACCESS_DENIED);
      if (findings != nullptr) {
        if (!AppendFinding(findings, service_name.c_str(), display_name.c_str(),
                           "path_heuristic", false, false, false, denied,
                           /*covered=*/false)) {
          ::CloseServiceHandle(manager);
          return 2;
        }
      }
      continue;
    }

    const std::string image_path = WideToUtf8(QueryConfigPath(service));
    ::CloseServiceHandle(service);

    if (image_path.empty()) {
      // 拿不到 ImagePath 就判不了。不能跳过——跳过的话这个驱动既不出现也不标
      // 未覆盖，读者只会以为「没有可疑驱动」。
      if (findings != nullptr) {
        if (!AppendFinding(findings, service_name.c_str(), display_name.c_str(),
                           "path_heuristic", false, false, false, false,
                           /*covered=*/false)) {
          ::CloseServiceHandle(manager);
          return 2;
        }
      }
      continue;
    }

    // 硬白名单先查：命中即完全不产生发现。
    if (options.hard_allowlist != nullptr &&
        is_hard_allowlisted(service_name, *options.hard_allowlist)) {
      continue;
    }

    // 判断顺序：先比文件名 IOC（更具体），再比路径位置。
    // 剥掉可能的参数段——驱动 ImagePath 偶尔带 <\??\...> 前缀。
    std::string bare = strip_quotes_and_args(image_path);
    if (bare.compare(0, 4, "\\??\\") == 0) {
      bare = bare.substr(4);
    }

    const ioc::NameRule* rule = DriverNameRule(StemOfPath(bare));
    std::string criteria;
    const char* evidence_url = nullptr;

    if (rule != nullptr) {
      criteria = "name_match";
      evidence_url = rule->evidence_url;
    } else {
      const std::string lowered = ToLowerAscii(bare);
      bool inside_known_dir = false;
      for (const wchar_t* dir : kDriverDirs) {
        const std::string dir_utf8 = ToLowerAscii(WideToUtf8(dir));
        if (lowered.rfind(dir_utf8, 0) == 0) {
          inside_known_dir = true;
          break;
        }
      }
      if (!inside_known_dir) {
        criteria = "path_heuristic";
      }
    }

    if (criteria.empty()) {
      continue;  // 名字没命中、路径也在该在的地方：干净驱动
    }

    if (findings != nullptr) {
      // evidence 目前找不到字段放（YhFinding 固定三段字符串），出处写在
      // IOC 表的注释里。需要把它透到报告的话要在 ABI 里加字段，
      // 一期先不加——宁可出处只有代码里一份，也不为它改 ABI。
      (void)evidence_url;
      if (!AppendFinding(findings, service_name.c_str(), bare.c_str(), criteria.c_str(),
                         /*attributes_verified=*/false, /*hidden=*/false, /*system=*/false,
                         /*elevation_required=*/false, /*covered=*/true)) {
        ::CloseServiceHandle(manager);
        return 2;
      }
    }
  }

  ::CloseServiceHandle(manager);
  return 0;
}

}  // namespace internal
}  // namespace yh
