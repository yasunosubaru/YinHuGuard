// engine/src/engine.cpp
//
// spec §3.1 的 C ABI 实现。这一层只做三件事：持有配置、把三段扫描接起来、
// 管内存与错误文本。全部 Win32 访问都在被调用的扫描文件里。
//
// 为什么多导出一个 yh_last_error：C ABI 没有异常，而 spec §2 硬约束 3 要求
// 「配置非法必须拒绝启动并**给出明确错误、指名键名**」。只有返回码的话那个键名
// 传不到界面，硬约束就落不了地。它是 spec §3.1 八个符号之外的第 9 个。

#include "internal.h"

#include <cstdlib>
#include <string>

#include "yh_criteria.h"

namespace {

// 不透明句柄的真身。定义在这里而不在头文件里，Dart 侧只拿到 void*。
struct Engine {
  yh::Config config;
};

// 把配置里的判据集合打包给 services.cpp。
yh::internal::ServiceScanOptions OptionsOf(const yh::Config& config) {
  yh::internal::ServiceScanOptions options;
  options.interpreter_keywords = &config.service_interpreter_keywords;
  options.path_allow_prefixes = &config.service_path_allow_prefixes;
  options.hard_allowlist = &config.hard_allowlist;
  return options;
}

Engine* AsEngine(void* handle) { return static_cast<Engine*>(handle); }

}  // namespace

extern "C" {

void* yh_engine_create(const char* config_path) {
  yh::internal::SetLastErrorText("");
  if (config_path == nullptr) {
    yh::internal::SetLastErrorText("配置路径为空");
    return nullptr;
  }

  std::string error;
  std::unique_ptr<yh::Config> config = yh::load_config(config_path, &error);
  if (config == nullptr) {
    // load_config 已经把「哪个键不合法」写进 error，原样带到 yh_last_error。
    yh::internal::SetLastErrorText(error.empty() ? std::string("配置无效") : error);
    return nullptr;
  }

  Engine* engine = new (std::nothrow) Engine();
  if (engine == nullptr) {
    yh::internal::SetLastErrorText("分配引擎句柄失败");
    return nullptr;
  }
  engine->config = std::move(*config);
  return engine;
}

void yh_engine_destroy(void* handle) {
  delete AsEngine(handle);
}

int32_t yh_self_check(void* handle, YhSelfCheck* out) {
  Engine* engine = AsEngine(handle);
  if (engine == nullptr || out == nullptr) {
    yh::internal::SetLastErrorText("自检参数无效");
    return 1;
  }
  yh::internal::SetLastErrorText("");

  YhSelfCheck result = {};
  result.elevated = yh::internal::IsElevated() ? 1 : 0;

  // 进程计数与 scan_processes 同源（同一个 ScanProcesses，findings 传 nullptr），
  // 两份实现会漂移，而「未覆盖」正是靠这些计数才看得见。
  yh::internal::ProcessScanSummary process_summary;
  const int32_t process_code =
      yh::internal::ScanProcesses(&process_summary, nullptr);
  if (process_code != 0) {
    return process_code;
  }
  result.process_total = process_summary.process_total;
  result.process_path_resolved = process_summary.process_path_resolved;
  result.session0_visible = process_summary.session0_visible;
  result.process_unresolved_permission = process_summary.unresolved_permission;
  result.process_unresolved_other = process_summary.unresolved_other;

  yh::internal::ServiceScanSummary service_summary;
  const int32_t service_code = yh::internal::ScanServices(
      OptionsOf(engine->config), &service_summary, nullptr);
  if (service_code != 0) {
    return service_code;
  }
  result.services_total = service_summary.services_total;
  result.services_with_path = service_summary.services_with_path;
  result.services_unresolved_permission = service_summary.unresolved_permission;
  result.services_unresolved_other = service_summary.unresolved_other;

  *out = result;
  return 0;
}

int32_t yh_scan_processes(void* handle, YhFindingList* out) {
  if (out == nullptr) {
    yh::internal::SetLastErrorText("输出列表为空");
    return 1;
  }
  out->items = nullptr;
  out->count = 0;
  yh::internal::SetLastErrorText("");
  return yh::internal::ScanProcesses(nullptr, out);
}

int32_t yh_scan_run_keys(void* handle, YhFindingList* out) {
  if (out == nullptr) {
    yh::internal::SetLastErrorText("输出列表为空");
    return 1;
  }
  out->items = nullptr;
  out->count = 0;
  yh::internal::SetLastErrorText("");
  return yh::internal::ScanRunKeys(out);
}

int32_t yh_scan_services(void* handle, YhFindingList* out) {
  Engine* engine = AsEngine(handle);
  if (engine == nullptr || out == nullptr) {
    yh::internal::SetLastErrorText("扫描服务参数无效");
    return 1;
  }
  out->items = nullptr;
  out->count = 0;
  yh::internal::SetLastErrorText("");
  return yh::internal::ScanServices(OptionsOf(engine->config), nullptr, out);
}

int32_t yh_scan_registry_payloads(void* handle, YhFindingList* out) {
  if (out == nullptr) {
    yh::internal::SetLastErrorText("输出列表为空");
    return 1;
  }
  out->items = nullptr;
  out->count = 0;
  yh::internal::SetLastErrorText("");
  return yh::internal::ScanRegistryPayloads(out);
}

int32_t yh_scan_drivers(void* handle, YhFindingList* out) {
  Engine* engine = AsEngine(handle);
  if (engine == nullptr || out == nullptr) {
    yh::internal::SetLastErrorText("扫描驱动参数无效");
    return 1;
  }
  out->items = nullptr;
  out->count = 0;
  yh::internal::SetLastErrorText("");
  return yh::internal::ScanDrivers(out, OptionsOf(engine->config));
}

int32_t yh_scan_file_drops(void* handle, YhFindingList* out) {
  if (out == nullptr) {
    yh::internal::SetLastErrorText("输出列表为空");
    return 1;
  }
  out->items = nullptr;
  out->count = 0;
  yh::internal::SetLastErrorText("");
  return yh::internal::ScanFileDrops(out);
}

int32_t yh_scan_scheduled_tasks(void* handle, YhFindingList* out) {
  if (out == nullptr) {
    yh::internal::SetLastErrorText("输出列表为空");
    return 1;
  }
  out->items = nullptr;
  out->count = 0;
  yh::internal::SetLastErrorText("");
  return yh::internal::ScanScheduledTasks(out);
}

const char* yh_last_error(void) { return yh::internal::GetLastErrorText(); }

void yh_finding_list_free(YhFindingList* list) { yh::internal::FreeFindingList(list); }

void yh_string_free(char* s) { std::free(s); }

}  // extern "C"
