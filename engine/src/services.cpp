// engine/src/services.cpp
//
// 对应上游「扫描3/3：可疑服务」。上游做法是
//   reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v ImagePath
// 全量递归再逐行 findstr（作者自述要 1–3 分钟）。这里换成
// EnumServicesStatusExW + QueryServiceConfigW，同样的覆盖，快得多。
//
// 判据两条：
//   service_interpreter       —— 关键字集合忠实还原上游的六元集合，但匹配方式更严。
//                                上游的 findstr /i /C:"cmd /c" 是**字面子串**搜索，
//                                匹配不到 cmd.exe /c（恶意服务 ImagePath 的真实写法），
//                                所以上游在这一项上基本抓不到东西。详见 spec §4.3。
//   service_path_heuristic    —— 本项目唯一的**新增**判据：ImagePath 落在
//                                System32 / SysWOW64 之外。银狐常把自身副本直接注册成
//                                服务，ImagePath 就是个 exe 路径、不含解释器关键字。
//
// 硬白名单先查：命中即**完全不产生发现**。swprv 与它的数字混淆显示名
// MicrosoftSoftware2ShadowCop4yProvider 必须在这里被拦掉 —— 上游「解禁杀毒软件.bat」
// 把后者当银狐驱动 reg delete，等于抹掉 Windows 卷影复制服务。

#include "internal.h"

#include <winsvc.h>

#include <string>
#include <vector>

#include "yh_criteria.h"

namespace yh {
namespace internal {

namespace {

// 取服务的 ImagePath。lpBinaryPathName 可能为空（某些内核驱动没有用户态路径），
// 这种情况不算错误，只是没有可判的字符串。
bool QueryImagePath(SC_HANDLE service, std::string* image_path, bool* access_denied) {
  *access_denied = false;

  DWORD needed = 0;
  ::QueryServiceConfigW(service, nullptr, 0, &needed);
  if (needed == 0) {
    const DWORD err = ::GetLastError();
    *access_denied = (err == ERROR_ACCESS_DENIED);
    return false;
  }

  std::vector<BYTE> buffer(needed, 0);
  QUERY_SERVICE_CONFIGW* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
  if (!::QueryServiceConfigW(service, config, needed, &needed)) {
    const DWORD err = ::GetLastError();
    *access_denied = (err == ERROR_ACCESS_DENIED);
    return false;
  }
  if (config->lpBinaryPathName == nullptr) {
    return false;
  }
  *image_path = WideToUtf8(config->lpBinaryPathName);
  return true;
}

}  // namespace

int32_t ScanServices(const ServiceScanOptions& options, ServiceScanSummary* summary,
                     YhFindingList* findings) {
  ServiceScanSummary local = {};

  SC_HANDLE manager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
  if (manager == nullptr) {
    SetLastErrorText("无法打开服务控制管理器：OpenSCManager 失败");
    if (summary != nullptr) {
      *summary = local;
    }
    return 2;
  }

  // 两段式：先问需要多大缓冲，再分配。不要用固定大小 —— 服务数量与每条路径长度
  // 都随机器变化，固定缓冲会静默截断，而截断的服务名在报告里看不出来。
  DWORD needed = 0;
  DWORD returned = 0;
  DWORD resume = 0;
  ::EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr,
                          0, &needed, &returned, &resume, nullptr);
  if (needed == 0) {
    ::CloseServiceHandle(manager);
    if (summary != nullptr) {
      *summary = local;
    }
    return 0;  // 零个服务：不是错误
  }

  std::vector<BYTE> buffer(needed, 0);
  resume = 0;
  returned = 0;
  if (!::EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buffer.data(), needed, &needed, &returned, &resume, nullptr)) {
    ::CloseServiceHandle(manager);
    SetLastErrorText("枚举服务失败：EnumServicesStatusExW 失败");
    if (summary != nullptr) {
      *summary = local;
    }
    return 2;
  }

  ENUM_SERVICE_STATUS_PROCESSW* entries =
      reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

  for (DWORD i = 0; i < returned; ++i) {
    local.services_total += 1;
    const std::string service_name = WideToUtf8(entries[i].lpServiceName);

    SC_HANDLE service = ::OpenServiceW(manager, entries[i].lpServiceName,
                                       SERVICE_QUERY_CONFIG);
    if (service == nullptr) {
      const bool access_denied = (::GetLastError() == ERROR_ACCESS_DENIED);
      if (access_denied) {
        local.unresolved_permission += 1;
      } else {
        local.unresolved_other += 1;
      }
      if (findings != nullptr) {
        if (!AppendFinding(findings, service_name.c_str(), service_name.c_str(),
                           "service_path_heuristic", /*attributes_verified=*/false,
                           /*hidden=*/false, /*system=*/false, access_denied,
                           /*covered=*/false)) {
          ::CloseServiceHandle(manager);
          FreeFindingList(findings);
          SetLastErrorText("追加服务发现时内存分配失败");
          if (summary != nullptr) {
            *summary = local;
          }
          return 2;
        }
      }
      continue;
    }

    std::string image_path;
    bool access_denied = false;
    const bool got_path = QueryImagePath(service, &image_path, &access_denied);
    ::CloseServiceHandle(service);

    if (!got_path || image_path.empty()) {
      // 拿不到 ImagePath：判不了，记未覆盖（权限不够时标注需要提权）。
      if (access_denied) {
        local.unresolved_permission += 1;
      } else {
        local.unresolved_other += 1;
      }
      if (findings != nullptr) {
        if (!AppendFinding(findings, service_name.c_str(), service_name.c_str(),
                           "service_path_heuristic", /*attributes_verified=*/false,
                           /*hidden=*/false, /*system=*/false, access_denied,
                           /*covered=*/false)) {
          ::CloseServiceHandle(manager);
          FreeFindingList(findings);
          SetLastErrorText("追加服务发现时内存分配失败");
          if (summary != nullptr) {
            *summary = local;
          }
          return 2;
        }
      }
      continue;
    }

    local.services_with_path += 1;

    // 硬白名单：命中即完全不产生发现。
    if (options.hard_allowlist != nullptr &&
        is_hard_allowlisted(service_name, *options.hard_allowlist)) {
      continue;
    }

    // 判据组合在 criteria.cpp 里，由单元测试盯着 —— 这两条判据分开调用时
    // 各自都对，错只存在于组合里（曾把剥过参数的串喂给 matches_interpreter，
    // 于是 `/c` 被删、解释器判据永远不命中）。这里只负责传**原始** ImagePath。
    std::vector<std::string> no_prefixes;
    const std::string criteria = classify_service_path(
        image_path,
        options.interpreter_keywords != nullptr ? *options.interpreter_keywords
                                                : no_prefixes,
        options.path_allow_prefixes != nullptr ? *options.path_allow_prefixes : no_prefixes);
    if (criteria.empty()) {
      continue;  // 干净服务
    }

    if (findings != nullptr) {
      // 服务判据不看文件属性（查的是 ImagePath 的形状），所以 attributes_verified
      // 保持 false —— 它表示「本条依据的不是文件属性」，不是「读了但读失败」。
      if (!AppendFinding(findings, service_name.c_str(), image_path.c_str(), criteria.c_str(),
                         /*attributes_verified=*/false, /*hidden=*/false, /*system=*/false,
                         /*elevation_required=*/false, /*covered=*/true)) {
        ::CloseServiceHandle(manager);
        FreeFindingList(findings);
        SetLastErrorText("追加服务发现时内存分配失败");
        if (summary != nullptr) {
          *summary = local;
        }
        return 2;
      }
    }
  }

  ::CloseServiceHandle(manager);
  if (summary != nullptr) {
    *summary = local;
  }
  return 0;
}

}  // namespace internal
}  // namespace yh
