// engine/src/processes.cpp
//
// 对应上游「扫描1/3：隐藏进程」。判据**忠实还原**（文件带 H 或 S 属性就算命中），
// 枚举方式**修正**两处上游缺陷：
//
//   1) 上游用 Get-WmiObject Win32_Process，再 Where-Object {$_.ExecutablePath -ne $null}。
//      实测本机 690 个进程中 Session 0 的 220 个 ExecutablePath 100% 为空 —— 那道过滤
//      把银狐最需要藏身的全部系统进程静默丢弃且不报错。这里改用
//      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) + QueryFullProcessImageNameW，
//      取不到路径的**照样产出 covered=0 的条目**，不消失。
//   2) 上游 Sort-Object -Unique 去重。保留，但改成大小写不敏感 —— Windows 路径不分区分大小写。
//
// 这里的判据命中不区分「进程名」：spec §4.4 的代码签名校验已移出一期，因此
// 白名单折叠（process_allowlist / 用户白名单）在 Dart 侧做，本文件只产出观测。

#include "internal.h"

#include <tlhelp32.h>

#include <set>
#include <vector>

#include "yh_criteria.h"

namespace yh {
namespace internal {

namespace {

// 取进程完整映像路径。失败时 *access_denied 区分「权限不够」与「进程已退出/其它」，
// 前者记 elevation_required，后者不记 —— 两者的成因完全不同，报告里不该混为一谈。
bool ResolveProcessPath(DWORD pid, std::wstring* path, bool* access_denied) {
  *access_denied = false;
  HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) {
    const DWORD err = ::GetLastError();
    *access_denied = (err == ERROR_ACCESS_DENIED);
    return false;
  }
  // 长路径：MAX_PATH 不够，32768 是 NT 命名空间的上限量级。
  std::vector<wchar_t> buffer(32768, L'\0');
  DWORD size = static_cast<DWORD>(buffer.size());
  const bool ok = ::QueryFullProcessImageNameW(process, 0, buffer.data(), &size) != FALSE;
  ::CloseHandle(process);
  if (!ok) {
    return false;
  }
  path->assign(buffer.data(), size);
  return true;
}

bool IsSessionZero(DWORD pid) {
  DWORD session = 0;
  if (!::ProcessIdToSessionId(pid, &session)) {
    return false;  // 问不出来就不算，宁可少算不可多算
  }
  return session == 0;
}

}  // namespace

int32_t ScanProcesses(ProcessScanSummary* summary, YhFindingList* findings) {
  ProcessScanSummary local = {};

  HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    SetLastErrorText("无法创建进程快照：CreateToolhelp32Snapshot 失败");
    if (summary != nullptr) {
      *summary = local;
    }
    return 2;
  }

  // 去重键。已解析的用完整路径，未解析的只能用映像名 —— 拿不到路径时我们
  // 无法区分两个同名进程，硬造出 220 条同名的行反而让报告更难读；
  // 「有多少进程没看到」这件事由 summary 的三个计数负责说清楚。
  std::set<std::string> seen;

  PROCESSENTRY32W entry = {};
  entry.dwSize = sizeof(entry);
  BOOL more = ::Process32FirstW(snapshot, &entry);
  while (more) {
    local.process_total += 1;

    const DWORD pid = entry.th32ProcessID;
    std::wstring wide_path;
    bool access_denied = false;
    const bool resolved = ResolveProcessPath(pid, &wide_path, &access_denied);

    const std::string exe_name = WideToUtf8(entry.szExeFile);

    // 解析成功但拿到空串，等同于没解析出来：没有路径就判不了属性，
    // 而且空串会把去重键压成 ""，之后每一条空路径都被它吃掉，
    // 整个扫描面塌成一条、然后那一条又过不了属性检查而消失。
    const std::string utf8_path = resolved ? WideToUtf8(wide_path) : std::string();
    const bool path_ok = !utf8_path.empty();

    std::string locator;
    std::string display_name;

    if (path_ok) {
      local.process_path_resolved += 1;
      if (IsSessionZero(pid)) {
        local.session0_visible += 1;
      }
      locator = utf8_path;
      display_name = exe_name;
    } else {
      locator = exe_name;
      display_name = exe_name;
    }

    const std::string dedup_key = ToLowerAscii(locator);
    if (!seen.insert(dedup_key).second) {
      more = ::Process32NextW(snapshot, &entry);
      continue;
    }

    if (findings != nullptr) {
      bool emit = false;
      bool hidden = false;
      bool system = false;
      bool attributes_verified = false;
      bool covered = true;

      if (path_ok) {
        const std::wstring wide = Utf8ToWide(locator);
        const DWORD attrs =
            wide.empty() ? INVALID_FILE_ATTRIBUTES : ::GetFileAttributesW(wide.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
          // 路径拿到了、属性却读不出来 —— 必须记未覆盖，不能跳过。
          // 跳过的话这条进程既不出现也不被标未覆盖，而它已经被计进
          // process_path_resolved（自检看着健康），发现列表却朝空收缩。
          // 「镜像文件读不出来」本身就是一种持久化手法。
          emit = true;
          covered = false;
          attributes_verified = false;
        } else {
          attributes_verified = true;
          if (has_hidden_or_system(static_cast<uint32_t>(attrs))) {
            emit = true;
            hidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
            system = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;
          }
        }
      } else {
        // 未取到路径：这是一条「未覆盖」，必须看得见（spec §5 的 covered 语义）。
        emit = true;
        covered = false;
        attributes_verified = false;
      }

      if (emit) {
        if (!AppendFinding(findings, locator.c_str(), display_name.c_str(), "file_attr_hs",
                           attributes_verified, hidden, system, access_denied, covered)) {
          ::CloseHandle(snapshot);
          FreeFindingList(findings);
          SetLastErrorText("追加进程发现时内存分配失败");
          if (summary != nullptr) {
            *summary = local;
          }
          return 2;
        }
      }
    }

    more = ::Process32NextW(snapshot, &entry);
  }

  ::CloseHandle(snapshot);
  if (summary != nullptr) {
    *summary = local;
  }
  return 0;
}

}  // namespace internal
}  // namespace yh
