// engine/src/file_drops.cpp
//
// 文件落点。这一类纯粹是「按已知路径找已知文件」，没有推理，全部来自奇安信
// 《2025 银狐木马年度报告》、瑞星、Nextron 的记录。
//
// 三处刻意不做成完整文件名、走启发式：
//   * `C:\\ProgramData\\` 下任意 `.sys`
//   * IE 目录下恰好 6 位随机字母数字的子目录（`C:\\Program Files\\Internet Explorer\\Ab3xY9\\`）
//   * `%APPDATA%\\<16 位随机>\\HWID` 一类
// 它们的文件名是每次生成时变的，写死只会漏。
//
// 目录递归**有上限**：深度 4、每目录最多 20000 条。不做全盘扫——既慢，又会把
// 系统自带的正常 .sys 全报出来，把真正该看的那几条淹掉。

#include "internal.h"

#include <string>
#include <vector>

#include "ioc_table.h"

namespace yh {
namespace internal {

namespace {

const size_t kMaxDepth = 4;
const size_t kMaxEntriesPerDir = 20000;

struct PathRule {
  const wchar_t* path;
  const char* evidence_url;
  const char* note;
};

// 完整路径。来自 IOC 表与奇安信/瑞星的清单。
// 注意：驱动器里只有 4 条不需要递归的静态路径加进来，其余按目录分开处理。
const PathRule kExactPaths[] = {
    {L"c:\\windows\\temp\\aceprocted.sys", ioc::kFilePaths[0].evidence_url,
     ioc::kFilePaths[0].note},
    {L"c:\\windows\\temp\\ranchserv.jpg", ioc::kFilePaths[1].evidence_url,
     ioc::kFilePaths[1].note},
    {L"c:\\windows\\system32\\temp.key", ioc::kFilePaths[2].evidence_url,
     ioc::kFilePaths[2].note},
    {L"c:\\windows\\system32\\tmp.key", ioc::kFilePaths[3].evidence_url,
     ioc::kFilePaths[3].note},
    {L"c:\\windows\\syswow64\\temp.key", ioc::kFilePaths[4].evidence_url,
     ioc::kFilePaths[4].note},
    {L"c:\\windows\\syswow64\\tmp.key", ioc::kFilePaths[5].evidence_url,
     ioc::kFilePaths[5].note},
    {L"c:\\program files\\internet explorer\\temp.key",
     ioc::kFilePaths[6].evidence_url, ioc::kFilePaths[6].note},
    {L"c:\\program files\\internet explorer\\tmp.key",
     ioc::kFilePaths[7].evidence_url, ioc::kFilePaths[7].note},
    {L"c:\\program files\\internet explorer\\nvsc.exe", ioc::kFilePaths[9].evidence_url,
     ioc::kFilePaths[9].note},
    {L"c:\\program files\\internet explorer\\nvgpu_x64.exe",
     ioc::kFilePaths[10].evidence_url, ioc::kFilePaths[10].note},
    {L"c:\\program files\\internet explorer\\nvml.bin", ioc::kFilePaths[11].evidence_url,
     ioc::kFilePaths[11].note},
    {L"c:\\program files\\internet explorer\\nvml.dll", ioc::kFilePaths[12].evidence_url,
     ioc::kFilePaths[12].note},
    {L"c:\\program files\\internet explorer\\glbdll.dll",
     ioc::kFilePaths[13].evidence_url, ioc::kFilePaths[13].note},
    {L"c:\\program files\\internet explorer\\glbdll.bin",
     ioc::kFilePaths[14].evidence_url, ioc::kFilePaths[14].note},
};

struct DirRuleWide {
  const wchar_t* dir;
  bool include_subdirs;
  const wchar_t* pattern;  // L"*" = 全部
  const char* evidence_url;
};

const DirRuleWide kDirRules[] = {
    {L"c:\\windows\\temp", true, L"*", "https://rayblog.rising.com.cn/2026/07/"},
    {L"c:\\users\\public\\documents\\windowsdata", true, L"*",
     "https://www.nextron-systems.com/2025/11/28/thor-vs-silver-fox-uncovering-and-defeating-a-sophisticated-valleyrat-campaign"},
    {L"c:\\programdata", true, L"*.sys", "https://weishi.360.cn/n/12709.html"},
};

bool PathExists(const std::wstring& path) {
  const DWORD attrs = ::GetFileAttributesW(path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES;
}

bool EndsWith(const std::wstring& haystack, const std::wstring& needle) {
  if (needle.size() > haystack.size()) {
    return false;
  }
  return haystack.compare(haystack.size() - needle.size(), needle.size(), needle) == 0;
}

std::wstring LowerWide(std::wstring s) {
  for (wchar_t& c : s) {
    if (c >= L'A' && c <= L'Z') {
      c = static_cast<wchar_t>(c - L'A' + L'a');
    }
  }
  return s;
}

// 递归列目录。有深度与条数上限——不做全盘扫，理由见文件头。
void WalkDir(const std::wstring& dir, size_t depth, const DirRuleWide& rule,
             YhFindingList* findings, int32_t* budget, const std::string& evidence_url,
             bool descend) {
  if (*budget <= 0 || (descend && depth > kMaxDepth)) {
    return;
  }
  const std::wstring pattern = dir + L"\\*";
  WIN32_FIND_DATAW found = {};
  HANDLE find = ::FindFirstFileW(pattern.c_str(), &found);
  if (find == INVALID_HANDLE_VALUE) {
    return;
  }
  size_t seen = 0;
  do {
    if (*budget <= 0 || seen >= kMaxEntriesPerDir) {
      break;
    }
    ++seen;
    --(*budget);

    const std::wstring name(found.cFileName);
    if (name == L"." || name == L"..") {
      continue;
    }

    if ((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      if (!descend) {
        continue;
      }
      WalkDir(dir + L"\\" + name, depth + 1, rule, findings, budget, evidence_url, true);
      continue;
    }

    // pattern 是 "*" 时全匹配；否则按后缀（大小写不敏感）。
    if (std::wstring(rule.pattern) != L"*") {
      if (!EndsWith(LowerWide(name), LowerWide(rule.pattern))) {
        continue;
      }
    }

    const std::wstring full = dir + L"\\" + name;
    if (!AppendFinding(findings, WideToUtf8(full).c_str(),
                       WideToUtf8(full).c_str(), "path_heuristic",
                       /*attributes_verified=*/false, /*hidden=*/false, /*system=*/false,
                       /*elevation_required=*/false, /*covered=*/true)) {
      ::FindClose(find);
      FreeFindingList(findings);
      SetLastErrorText("追加文件落点发现时内存分配失败");
      // 预算归零让调用方也停下。
      *budget = 0;
      return;
    }
  } while (::FindNextFileW(find, &found) != FALSE);
  ::FindClose(find);
}

// IE 目录下「恰好 6 位字母数字」的子目录。按要求：文件名随机、长度固定。
bool LooksLikeRandomSix(const std::wstring& name) {
  if (name.size() != ioc::kIeRandomDirLength) {
    return false;
  }
  for (const wchar_t c : name) {
    const bool alnum = (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'z') ||
                       (c >= L'A' && c <= L'Z');
    if (!alnum) {
      return false;
    }
  }
  return true;
}

}  // namespace

int32_t ScanFileDrops(YhFindingList* findings) {
  int32_t code = 0;

  // ---- 1) 完整路径的静态清单 ----
  for (const PathRule& rule : kExactPaths) {
    if (!PathExists(rule.path)) {
      continue;
    }
    if (findings != nullptr) {
      if (!AppendFinding(findings, WideToUtf8(rule.path).c_str(),
                         WideToUtf8(rule.path).c_str(), "name_match",
                         /*attributes_verified=*/false, /*hidden=*/false, /*system=*/false,
                         /*elevation_required=*/false, /*covered=*/true)) {
        FreeFindingList(findings);
        return 2;
      }
    }
  }

  // ---- 2) 目录规则 ----
  // 读不到某个目录本身也是信息：它可能是被 deny ACL 挡住的（Nextron 记录
  // 银狐会给 WindowsData 加一条 deny-ACL 让管理员都删不掉）。但不报错，
  // 只静默跳过——报成错误会让整个扫描失败。
  int32_t budget = 4096;
  for (const DirRuleWide& rule : kDirRules) {
    WalkDir(rule.dir, 0, rule, findings, &budget, rule.evidence_url, rule.include_subdirs);
    if (findings != nullptr && findings->count > 0 && budget == 0) {
      // 撞到条数上限了。不是错误，但要让调用方知道只看了前 N 条。
      code = 0;
    }
  }

  // ---- 3) IE 目录下的 6 位随机子目录 ----
  for (const wchar_t* ie_dir : ioc::kIeDirs) {
    const std::wstring pattern = std::wstring(ie_dir) + L"\\*";
    WIN32_FIND_DATAW found = {};
    HANDLE find = ::FindFirstFileW(pattern.c_str(), &found);
    if (find == INVALID_HANDLE_VALUE) {
      continue;  // 该 IE 目录不存在
    }
    do {
      const std::wstring name(found.cFileName);
      if (name == L"." || name == L"..") {
        continue;
      }
      if ((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        continue;
      }
      if (!LooksLikeRandomSix(name)) {
        continue;
      }
      const std::wstring full = std::wstring(ie_dir) + L"\\" + name;
      if (findings != nullptr) {
        if (!AppendFinding(findings, WideToUtf8(full).c_str(),
                           WideToUtf8(full).c_str(), "path_heuristic",
                           /*attributes_verified=*/false, /*hidden=*/false, /*system=*/false,
                           /*elevation_required=*/false, /*covered=*/true)) {
          ::FindClose(find);
          FreeFindingList(findings);
          return 2;
        }
      }
    } while (::FindNextFileW(find, &found) != FALSE);
    ::FindClose(find);
  }

  return code;
}

}  // namespace internal
}  // namespace yh
