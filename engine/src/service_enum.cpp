// engine/src/service_enum.cpp
//
// EnumerateServicesRaw 的实现。

#include "service_enum.h"

namespace yh {
namespace internal {

bool EnumerateServicesRaw(SC_HANDLE manager, DWORD service_type,
                          std::vector<BYTE>* buffer, DWORD* out_count) {
  buffer->clear();
  if (out_count != nullptr) {
    *out_count = 0;
  }
  if (manager == nullptr) {
    return false;
  }

  // 先问需要多大。返回 0 表示零个条目——这是合法结果，不是错误。
  DWORD needed = 0;
  DWORD returned = 0;
  DWORD resume = 0;
  ::EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, service_type, SERVICE_STATE_ALL,
                          nullptr, 0, &needed, &returned, &resume, nullptr);
  if (needed == 0) {
    return true;  // 零个服务
  }

  // 固定大小缓冲会在这里静默截断：服务多几台就少列几台，而少列的那些在报告
  // 里完全看不出来。所以必须按 needed 分配。
  buffer->assign(needed, 0);
  resume = 0;
  returned = 0;
  if (!::EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, service_type,
                               SERVICE_STATE_ALL, buffer->data(),
                               static_cast<DWORD>(buffer->size()), &needed, &returned,
                               &resume, nullptr)) {
    return false;
  }
  if (out_count != nullptr) {
    *out_count = returned;
  }
  return true;
}

}  // namespace internal
}  // namespace yh
