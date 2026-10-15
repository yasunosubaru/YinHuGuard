// engine/src/scheduled_tasks.cpp
//
// 计划任务。四项里最重的一处：要走 Task Scheduler COM。
//
// **为什么用 taskschd.h 而不是手写 vtable 索引**：ITaskFolder / IRegisteredTask
// 都派生自 IDispatch，vtable 偏移是中规中距的一堆数字。凭记忆抄一份的后果是
// 调用了错误的槽位，表现为「枚举到任务但取不到 action」——一个静默的空结果。
// 所以接口全部来自微软的 taskschd.h（SDK 自带的 425KB 声明），偏移由编译器
// 从类型库生成，不含任何记忆成分。
//
// 判据两条：
//   name_match       —— 任务名 / 任务 XML 文件名命中 IOC 表
//   path_heuristic   —— 任务的 action 路径不在 System32 / SysWOW64
//
// 为什么 commands 之外还扫文件：任务 XML 定义文件（Pocy.xml 等）落盘时
// 任务本身可能已被删或改名，只枚举活动任务会漏掉它们。

#include "internal.h"

// COM 接口声明来自 SDK，不写手工的 vtable 索引。
#include <comdef.h>
#include <objbase.h>
#include <taskschd.h>

#ifdef _M_X64
#pragma comment(lib, "taskschd.lib")
#endif

#include <shlwapi.h>  // PathMatchSpecW 不需要，这里只用 FindFirstFileW

#include <string>
#include <vector>

#include "ioc_table.h"
#include "yh_criteria.h"

namespace yh {
namespace internal {

#ifdef _M_X64

namespace {

// COM 对象的 RAII。COM 接口方法返回值是 HRESULT，忘了判失败就是野指针，
// 而这个代码块里失败路径特别多，所以每个出口都必须收尾。
template <typename T>
class ComPtr {
 public:
  ComPtr() = default;
  ~ComPtr() {
    if (p_ != nullptr) {
      p_->Release();
      p_ = nullptr;
    }
  }
  ComPtr(const ComPtr&) = delete;
  ComPtr& operator=(const ComPtr&) = delete;

  T* operator->() const { return p_; }
  T** operator&() { return &p_; }
  /// 隐式转出裸指针：COM 的 get_Item 之类会以「指针出参 + 野指针入参」交替出现，
  /// 不转的话调用点全是显式 .get()，既啰嗦又容易漏判 FAILED。
  operator T*() const { return p_; }
  explicit operator bool() const { return p_ != nullptr; }

 private:
  T* p_ = nullptr;
};

std::string WideToUtf8Bstr(const _bstr_t& text) {
  if (text.length() == 0) {
    return std::string();
  }
  return WideToUtf8(std::wstring(static_cast<const wchar_t*>(text)));
}

std::string WideToUtf8Bstr(const _variant_t& v) {
  if (v.vt != VT_BSTR || v.bstrVal == nullptr) {
    return std::string();
  }
  return WideToUtf8(std::wstring(v.bstrVal));
}

// 任务名或 XML 文件名是否命中 IOC 表。命中时给出处。
const ioc::NameRule* TaskNameRule(const std::string& name) {
  const std::string lowered = ToLowerAscii(name);
  for (const ioc::NameRule& rule : ioc::kTaskNames) {
    const std::string rule_lowered = ToLowerAscii(rule.name);
    if (lowered == rule_lowered ||
        lowered.find(rule_lowered) != std::string::npos) {
      return &rule;
    }
  }
  return nullptr;
}

// XML 定义文件的 basename 命中。
const ioc::NameRule* TaskDefinitionFileRule(const std::string& name) {
  const std::string lowered = ToLowerAscii(name);
  for (const ioc::NameRule& rule : ioc::kTaskDefinitionFiles) {
    if (lowered.find(ToLowerAscii(rule.name)) != std::string::npos) {
      return &rule;
    }
  }
  return nullptr;
}

const wchar_t* const kTaskActionAllowedPrefixes[] = {
    L"c:\\windows\\system32",
    L"c:\\windows\\syswow64",
};

bool ActionPathIsSuspicious(const std::string& path) {
  if (path.empty()) {
    return false;
  }
  const std::string lowered = ToLowerAscii(path);
  for (const wchar_t* prefix : kTaskActionAllowedPrefixes) {
    if (lowered.rfind(ToLowerAscii(WideToUtf8(prefix)), 0) == 0) {
      return false;
    }
  }
  return true;
}

struct TaskVisit {
  YhFindingList* findings = nullptr;
  const ServiceScanOptions* options = nullptr;
  int32_t code = 0;
};

// 把一个已枚举到的任务上报。
void ReportTask(TaskVisit* visit, const std::string& task_path,
                const std::string& task_name, const std::string& action_path,
                const ioc::NameRule* rule) {
  std::string criteria;
  if (rule != nullptr) {
    criteria = "name_match";
  } else if (ActionPathIsSuspicious(action_path)) {
    criteria = "path_heuristic";
  } else {
    return;  // 干净的微软任务
  }

  // locator 用任务路径（...\Name），display_name 用 action 路径 ——
  // 报告里要能看出「这个任务到底干了什么」。
  const std::string locator =
      task_path.empty() ? task_name : task_path + "\\" + task_name;

  (void)visit->options;
  if (visit->findings == nullptr) {
    return;
  }
  if (!AppendFinding(visit->findings, locator.c_str(), action_path.c_str(),
                     criteria.c_str(), /*attributes_verified=*/false,
                     /*hidden=*/false, /*system=*/false,
                     /*elevation_required=*/false, /*covered=*/true)) {
    visit->code = 2;
  }
}

// 取任务的 action 路径。失败返回空串——不能跳过调用方，否则就变成「没有
// 可疑任务」。
std::string TaskActionPath(IRegisteredTask* task) {
  ComPtr<ITaskDefinition> definition;
  if (task == nullptr || FAILED(task->get_Definition(&definition))) {
    return std::string();
  }
  ComPtr<IActionCollection> actions;
  if (FAILED(definition->get_Actions(&actions))) {
    return std::string();
  }
  long count = 0;
  if (FAILED(actions->get_Count(&count))) {
    return std::string();
  }
  std::string result;
  for (long i = 1; i <= count; ++i) {
    ComPtr<IAction> action;
    if (FAILED(actions->get_Item(_variant_t(i), &action))) {
      continue;
    }
    TASK_ACTION_TYPE type = TASK_ACTION_EXEC;
    if (FAILED(action->get_Type(&type)) || type != TASK_ACTION_EXEC) {
      continue;  // 只追可执行动作；COM 邮件/消息动作与本次判定无关
    }
    ComPtr<IExecAction> exec;
    if (action->QueryInterface(__uuidof(IExecAction),
                               reinterpret_cast<void**>(&exec)) != S_OK) {
      continue;
    }
    BSTR path = nullptr;
    if (SUCCEEDED(exec->get_Path(&path)) && path != nullptr) {
      result += WideToUtf8(std::wstring(path));
      ::SysFreeString(path);
      if (i < count) {
        result += " | ";
      }
    }
  }
  return result;
}

// 递归遍历任务文件夹。深度有上限：任务路径一般只有两三层，过深八成是配置异常。
void WalkFolder(ITaskFolder* folder, TaskVisit* visit, int depth) {
  if (visit->code != 0 || folder == nullptr || depth > 8) {
    return;
  }

  ComPtr<IRegisteredTaskCollection> tasks;
  if (SUCCEEDED(folder->GetTasks(0, &tasks))) {
    long count = 0;
    if (SUCCEEDED(tasks->get_Count(&count))) {
      for (long i = 1; i <= count && visit->code == 0; ++i) {
        ComPtr<IRegisteredTask> task;
        if (FAILED(tasks->get_Item(_variant_t(i), &task))) {
          continue;
        }
        BSTR name = nullptr;
        BSTR path = nullptr;
        std::string task_name;
        std::string task_path;
        if (SUCCEEDED(task->get_Name(&name)) && name != nullptr) {
          task_name = WideToUtf8(std::wstring(name));
          ::SysFreeString(name);
        }
        if (SUCCEEDED(task->get_Path(&path)) && path != nullptr) {
          task_path = WideToUtf8(std::wstring(path));
          ::SysFreeString(path);
        }
        const ioc::NameRule* rule = TaskNameRule(task_name);
        if (rule == nullptr && !task_path.empty()) {
          rule = TaskNameRule(task_path);
        }
        ReportTask(visit, task_path, task_name, TaskActionPath(task), rule);
      }
    }
  }

  ComPtr<ITaskFolderCollection> subfolders;
  if (FAILED(folder->GetFolders(0, &subfolders))) {
    return;
  }
  long folder_count = 0;
  if (FAILED(subfolders->get_Count(&folder_count))) {
    return;
  }
  for (long i = 1; i <= folder_count && visit->code == 0; ++i) {
    ComPtr<ITaskFolder> subfolder;
    if (SUCCEEDED(subfolders->get_Item(_variant_t(i), &subfolder))) {
      WalkFolder(subfolder, visit, depth + 1);
    }
  }
}

// 落盘的 XML 定义文件。活动任务可能已被删或改名，但 XML 还留着。
void ScanTaskDefinitionFiles(TaskVisit* visit) {
  // 严重错误只能在有接入点时才算作枚举失败；这里已知目录不存在是正常的。
  const wchar_t* const roots[] = {
      L"c:\\windows\\system32\\tasks",
  };
  for (const wchar_t* root : roots) {
    WIN32_FIND_DATAW found = {};
    HANDLE find = nullptr;
    const std::wstring pattern = std::wstring(root) + L"\\*";
    find = ::FindFirstFileW(pattern.c_str(), &found);
    if (find == INVALID_HANDLE_VALUE) {
      continue;
    }
    do {
      const std::wstring name(found.cFileName);
      if (name == L"." || name == L"..") {
        continue;
      }
      const ioc::NameRule* rule = TaskDefinitionFileRule(WideToUtf8(name));
      if (rule == nullptr) {
        continue;
      }
      const std::wstring full = std::wstring(root) + L"\\" + name;
      if (visit->findings != nullptr) {
        if (!AppendFinding(visit->findings, WideToUtf8(full).c_str(),
                           WideToUtf8(full).c_str(), "name_match",
                           /*attributes_verified=*/false, /*hidden=*/false,
                           /*system=*/false, /*elevation_required=*/false,
                           /*covered=*/true)) {
          ::FindClose(find);
          visit->code = 2;
          return;
        }
      }
    } while (::FindNextFileW(find, &found) != FALSE);
    ::FindClose(find);
    (void)find;
  }
}

}  // namespace

#endif  // _M_X64

int32_t ScanScheduledTasks(YhFindingList* findings) {
#ifdef _M_X64
  // x64 才有 Task Scheduler 2.0 的 COM 接口（1.0 的在 at.exe / 只在老系统上）。
  // 别的架构直接返回 0 并在 findings 里记一条未覆盖，而不是静默返回空。
  HRESULT init = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  const bool init_owned = (init == S_OK);
  if (init_owned || init == S_FALSE || init == RPC_E_CHANGED_MODE) {
    TaskVisit visit;
    visit.findings = findings;
    visit.code = 0;

    int32_t result = 0;
    {
      ComPtr<ITaskService> service;
      HRESULT created = ::CoCreateInstance(CLSID_TaskScheduler, nullptr,
                                           CLSCTX_INPROC_SERVER, IID_ITaskService,
                                           reinterpret_cast<void**>(&service));
      if (FAILED(created)) {
        // 建不出 Task Scheduler（老系统 / 服务被禁）。记一条未覆盖，别静默。
        if (findings != nullptr) {
          AppendFinding(findings, "ITaskService", "", "name_match", false, false, false,
                        /*elevation_required=*/false, /*covered=*/false);
        }
        result = 2;
      } else {
        // Connect 的四个 VARIANT 是可选的；传 DISP_E_PARAMNOTFOUND 表示「用
        // 本机与当前凭据」。传空 VARIANT 也行，但那个原意是「空串」。
        _variant_t missing = _variant_t(DISP_E_PARAMNOTFOUND, VT_ERROR);
        if (FAILED(service->Connect(missing, missing, missing, missing))) {
          if (findings != nullptr) {
            AppendFinding(findings, "ITaskService.Connect", "", "name_match", false, false,
                          false, /*elevation_required=*/false, /*covered=*/false);
          }
          result = 2;
        } else {
          _bstr_t rootPath = L"\\";
          ComPtr<ITaskFolder> root;
          if (FAILED(service->GetFolder(rootPath, &root))) {
            if (findings != nullptr) {
              AppendFinding(findings, "ITaskFolder", "", "name_match", false, false, false,
                            /*elevation_required=*/false, /*covered=*/false);
            }
            result = 2;
          } else {
            WalkFolder(root, &visit, 0);
            ScanTaskDefinitionFiles(&visit);
            result = visit.code;
          }
        }
      }
    }

    if (init_owned) {
      ::CoUninitialize();
    }
    return result;
  }

  // COM 都初始化不了 —— 记未覆盖。
  if (findings != nullptr) {
    AppendFinding(findings, "COM", "", "name_match", false, false, false,
                  /*elevation_required=*/false, /*covered=*/false);
  }
  return 2;
#else   // x64
  (void)findings;
  return 2;
#endif  // _M_X64
}

}  // namespace internal
}  // namespace yh
