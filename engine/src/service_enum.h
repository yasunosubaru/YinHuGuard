// engine/src/service_enum.h
//
// 只抽一样东西出来共享：**两段式列出服务**。services.cpp 与 drivers.cpp 都要
// 枚举服务/驱动，各写一份会让那段最容易出静默错的代码出现两份实现——
// 固定大小缓冲会截断，而截断掉的服务名在报告里根本看不出来，只会表现成
// 「这台机器上没这个服务」。
//
// 抽出来的仅止于此。两边的遍历与判定差异很大，硬合并成一个回调签名只会把
// 调用点绕得难读。

#ifndef YH_SERVICE_ENUM_H_
#define YH_SERVICE_ENUM_H_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <vector>

#include <winsvc.h>

namespace yh {
namespace internal {

// 把 [service_type]（SERVICE_WIN32 或 SERVICE_DRIVER）的所有条目取到
// [buffer] 里，条目数写进 [out_count]。
//
// **「零个」与「枚举失败」必须区分开**：前者返回 true 且 out_count == 0，
// 后者返回 false。混为一谈的话，一个枚举失败会被读成「这台机器没有服务」。
bool EnumerateServicesRaw(SC_HANDLE manager, DWORD service_type,
                          std::vector<BYTE>* buffer, DWORD* out_count);

}  // namespace internal
}  // namespace yh

#endif  // YH_SERVICE_ENUM_H_
