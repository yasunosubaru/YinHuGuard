# YinHuGuard 一期设计规格

- 日期：2026-10-14
- 状态：已与用户确认（v2，收敛至原 bat 三段核心），待书面复核
- 工作区：`<workspace>/YinHuGuard`
- 上游：`银狐木马处理方案\YinHu病i毒清理脚本（9月27日更新）`（原作者 B 站 @SYSTEM-RAMOS-ZDY）

> **修订记录**
> - 2026-10-15：二期（(a) 完整扫描流程 / (b) 深度扫描四面）已实现。本文件正文描述的是**一期**范围，凡与二期冲突之处，以 **§13 二期变更记录**为准。改动点已在 §4.6、§7、§12 就地标注。

---

## 1. 定位与范围

单机、只读、离线的隐藏进程与可疑启动项**排查工具**。

一期**忠实重建上游 `查找隐藏的进程和启动项.bat` 的三段核心扫描**，修掉已确认的实现缺陷，不扩展扫描面。

**一期不做**：清理、修复、回滚；新增扫描面；联网更新；崩溃上报；代码签名；注入 / hook / 内存修改 / 驱动编写；安装包。

---

## 2. 三条硬约束

安全约束，不是偏好，不接受修改。

1. **只走可审计的公开接口。** Win32 访问限于进程查询、SCM 查询、注册表读取、文件属性读取、签名查询。禁止进程注入、API hook、内存读写、驱动加载。原因：清理远控木马的工具如果行为像远控木马，会被Defender 和第三方杀软优先隔离。
2. **微软系统服务进硬白名单。** 全部系统组件永不参与任何判定。**这条由代码强制，不由配置文件强制**——`swprv`、`vmservice`、`MicrosoftSoftware2ShadowCop4yProvider` 三项**硬编码在 C++ 里作为不可下调的地板**，`rules.json` 的 `hard_allowlist` 只能**追加**，不能删除或替换。手工编辑配置把该数组清空，不会让这三个名字重新变得可报。
3. **配置是纯数据。** `rules.json` 只含关键字、名单等字符串，程序只解析、只比较，**不执行、不eval**。

---

## 3. 架构

```
Flutter UI (Dart)          单页仪表盘 + 侧边栏落点树
│  仅通过这一层 FFI 接口 ▼
Scanner Engine (C++ DLL)   全部 Win32 访问收敛于此
      │
      ▼
rules.json (exe 旁)        纯数据配置
```

选择理由：

- **C++ DLL 而非 Dart 直接声明 FFI**——进程枚举、注册表遍历的结构体与回调很繁杂，散落在 Dart 侧是一堆易错的 ctypes 映射。收敛后改系统 API 只动一个文件。
- **弃用 WMI**——实测本机 690 个进程中，Session 0 的 220 个 `ExecutablePath` **100% 为空**。上游脚本的 `ExecutablePath -ne $null` 过滤把银狐最需要藏身的全部系统进程静默丢弃且不报错。改用 `NtQueryInformationProcess` + `QueryFullProcessImageNameW`；服务侧走 `QueryServiceConfigW`。

### 3.1 FFI 边界

三个扫描函数与上游三段扫描、上游的「扫描1/3、2/3、3/3」一一对应：

```c
typedef struct {
    char*   locator;              // 进程完整路径 / 注册表键路径 / 服务名
    char*   display_name;         // 界面展示用
    char*   criteria;             // "file_attr_hs" | "service_interpreter" | "service_path_heuristic"
    int32_t attributes_verified;  // 0 = 属性未知
    int32_t hidden;
    int32_t system;
    int32_t elevation_required;
    int32_t covered;              // 0 = 因权限不足未覆盖
    double  timestamp;            // unix 秒
} YhFinding;

typedef struct { YhFinding* items; size_t count; } YhFindingList;

typedef struct {
    int32_t elevated;
    int32_t process_total;
    int32_t process_path_resolved;
    int32_t session0_visible;
    int32_t services_total;
    int32_t services_with_path;
} YhSelfCheck;

void*   yh_engine_create(const char* config_path);
void    yh_engine_destroy(void* h);
int32_t yh_self_check(void* h, YhSelfCheck* out);
int32_t yh_scan_processes(void* h, YhFindingList* out);
int32_t yh_scan_run_keys(void* h, YhFindingList* out);
int32_t yh_scan_services(void* h, YhFindingList* out);
void    yh_finding_list_free(YhFindingList* l);
void    yh_string_free(char* s);
```

约定：返回 `0` 成功，非 `0` 为错误码。所有 `char*` 为 UTF-8，由 `yh_string_free` 释放。

---

## 4. 扫描面与判据

三个扫描面严格对应上游三段。每一段都注明是**忠实还原**还是**修正缺陷**。

### 4.1 `processes` —— 对应上游「扫描1/3：隐藏进程」

| 步骤 | 上游做法 | 本项目 |
|---|---|---|
| 枚举 | `Get-WmiObject Win32_Process` | **修正**：`NtQueryInformationProcess` + `QueryFullProcessImageNameW` |
| 取路径 | `Where-Object { $_.ExecutablePath -ne $null }` | **修正**：不做 `-ne $null` 过滤；取不到的记 `covered=0` |
| 去重 | `Sort-Object -Unique` | 保留 |
| 判据 | `%%~ap` + `findstr /i "h s"` 命中 H 或 S | 保留，这是上游唯一判据 |

### 4.2 `run_keys` —— 对应上游「扫描2/3：隐藏启动项」

| 键 | 保留 |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | 是 |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` | 是 |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | 是 |

判据链忠实还原：过滤 `REG_SZ` / `REG_EXPAND_SZ` → 从值数据提取引号内路径（无引号则取整串）→ 剥离尾随 `)` → `if exist` 判存在 → 读文件属性 → `H`/`S` 命中即报。

**修正**：上游所有取不到的路径经 `2^>nul` 静默丢弃。本项目记`covered=0` 并在 UI 明示「未覆盖」。

### 4.3 `services` —— 对应上游「扫描3/3：可疑服务」

上游做法：`reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v ImagePath` 全量递归，再逐行匹配解释器关键字。

| 判据 | 来源 |
|---|---|
| `service_interpreter` | **关键字集合忠实还原**：`cmd /c`、`powershell`、`wscript`、`cscript`、`mshta`、`pwsh`（上游原集合，不增不减）。**但匹配方式比上游更严，见下。** |
| `service_path_heuristic` | **新增**：`ImagePath` 指向 `C:\Windows\System32` 与 `C:\Windows\SysWOW64` 之外 |

**上游在 `cmd /c` 这一项上是坏的。** `findstr /i /C:"cmd /c"` 是**字面子串**搜索，要求待匹配文本里出现连续的 `cmd /c`。而恶意服务 `ImagePath` 的真实写法是 `C:\Windows\system32\cmd.exe /c "C:\path\a.bat"`——其中是 `cmd.exe /c`，**不含** `cmd /c`。上游因此在这一项上基本抓不到东西。其余五个单记号关键字是有效子串匹配，照搬即可。

本项目对 `cmd /c` 实现**按记号有序匹配**：拆成 `cmd` 与 `/c` 两段，前者须命中路径中某个 exe 词元的 stem、后者紧随其后（允许中间插入 `.exe`）。于是 `cmd.exe /c foo.bat` 命中，裸 `cmd.exe` 不命中。**这是有意的判定改进，不是还原。**

`service_path_heuristic` 是上游没有的**唯一新增判据**。保留它的理由：情报显示银狐常把自身副本直接注册为服务，`ImagePath` 是个 exe 路径、不含任何解释器关键字，上游原判据会直接漏掉。**如果要求严格零新增，删掉这一条即可，其余不变。**

上游用 `reg query` 全量递归，输出每个 `ImagePath` 行再过滤。本项目改用 `EnumServicesStatusExW` + `QueryServiceConfigW` 直接取 360 个服务的 `PathName`（实测 358 个有值），**省掉上游自述的 1–3 分钟**。

### 4.4 进程签名校验 —— **移出一期**

上游检测脚本对进程**没有任何过滤**，全报。情报指出银狐专门注入 `svchost` / `vssvc` / `explorer` / `winlogon`，进程名无法区分正常与被注入，因此曾规划加代码签名校验。

**该判据超出「原 bat 核心功能」范围，移出一期**，记为二期候选。

一期仅提供 `rules.json` 里的**用户白名单**（Q6 决策），不含签名校验。

### 4.5 硬白名单

以下永不参与任何判定：

- **全部微软系统服务**，含 `swprv`
- `vmservice`
- `MicrosoftSoftware2ShadowCop4yProvider` — 情报确认这是 `swprv`（Microsoft Software Shadow Copy Provider）的微软**数字混淆显示名**。上游 `解禁杀毒软件.bat` 把它当银狐驱动 `reg delete`，等于抹掉 Windows 卷影复制服务
- `vafdska`、`MiniFilterDrv` — 情报未找到任何银狐出处，作民间脚本产物处理，不作 IOC

### 4.6 移出一期的扫描面

> **⚠️ 2026-10-15 修订（二期）：下面这四个面已在二期实现**，判据见 §13。
> 「同样移出一期」的那一段（Winlogon / IFEO / WMI 事件订阅 / COM / DLL 侧载）
> **仍然不做**，理由不变：查不到银狐实际使用的公开证据，收进默认规则只是噪音。

以下均有厂商情报佐证，但超出「原 bat 核心功能」范围，**移出一期**：驱动服务、计划任务、注册表载荷、文件落点。

作为二期起点记录（情报示例）：`amsdk.sys`/`wamsdk.sys`/`BootRepair.sys`；`WindowsPowerShell.WbemScripting.SWbemLocator`、`HandleCommand`；`HKCU\Console\0`、`HKLM\SOFTWARE\IpDates_sun`、标记串 `FaCai2024`；`C:\Windows\Temp\aceprocted.sys`、`C:\ProgramData\*.sys`。

同样移出一期（**无银狐实证**，作通用后门手法，会产生噪音）：Winlogon 劫持、IFEO 映像劫持、WMI 事件订阅、COM/TypeLib 劫持、企业管控软件寄生、DLL 侧载。

---

## 5. 数据模型

```dart
class Finding {
  final String surface;          // processes | run_keys | services
  final String locator;          // 进程完整路径 / 注册表键路径 / 服务名
  final String displayName;
  final String criteria;         // file_attr_hs | service_interpreter | service_path_heuristic
  final bool attributesVerified;
  final bool hidden;
  final bool system;
  final bool elevationRequired;
  final bool covered;            // false = 权限不足未覆盖
  final DateTime timestamp;
  final bool allowlisted;        // 命中 rules.json 白名单，供 UI 折叠

  // 以下为一期占位，二期填充（见第 10 节）
  final double? confidence;
  final SuggestedAction? suggestedAction;
  final ChangeRecord? changeRecord;
}
```

`covered: false` 是**强制语义**：该项因权限不足未检查，UI 必须明示「未覆盖」，绝不能用空结果冒充「干净」。上游脚本的 `2^>nul` 正是这个错误。

`confidence` / `suggestedAction` / `changeRecord` 一期恒为 `null`。上游设计「照搬原脚本只看 H/S」因此一期不渲染颜色分级，分组与白名单折叠是仅有的两个扫读辅助。

---

## 6. 权限模型

- 只读扫描**免提权**启动
- 需要提权的项（Session 0 进程路径等）用 `ShellExecuteEx` + `runas` **逐项**弹 UAC
- 不做「一运行就 UAC」——只读扫描拿管理员权限没有正当理由，却让用户第一眼就怀疑这是恶意软件

实测基线（本机，用户态）：服务 360 个 / 358 个有 `PathName`，全可读；注册表三个 Run 键与 `Winlogon` 均可读；**Session 0 进程路径 100% 不可读**。

---

## 7. UI

> **⚠️ 2026-10-15 修订（二期）：第一条「打开即扫」有意未实现。** 实现为
> **点「开始扫描」才扫**，理由：一个安全工具在用户还没点任何东西时就去枚举
> 全机进程与服务，是最容易被当成恶意软件的行为，也把「我只是想看看这个程序
> 长什么样」变成一个已经发生了的系统访问。理由写在 `dashboard_page.dart` 开头。
> 同理，引擎句柄在第一次点扫描时才构造 —— 「打开程序」本身不加载 DLL、不读
> 配置、不碰系统。以下其余各条仍然有效（侧边栏已从三项扩到七项，见 §13）。

- **单页仪表盘，打开即扫**，进度条 + 结果实时追加，底部固定导出按钮。不做引导式向导
- **侧边栏三项落点树**（对应 4.1–4.3 的三个 `surface`）用于**切换查看**，不用于控制扫不扫
- 表格**默认按落点类型分组、组内时间倒序**
- **首屏放自检按钮**：实测并显示 Session 0 进程可见数、服务 `PathName` 覆盖率、是否已提权
- 文案走手写 `strings.dart` 字典（二期换 `gen-l10n` 只差换文件）
- 产品界面为中文，二期补英文

---

## 8. 配置文件 `rules.json`

外置在 exe 旁边，手工编辑、可复制传阅。程序零网络请求。

一期它是**配置**而非 IOC 库——因为一期没有名单匹配判据。

```json
{
  "schema_version": 1,
  "updated_at": "2026-10-14",
  "service_interpreter_keywords": ["cmd /c", "powershell", "wscript", "cscript", "mshta", "pwsh"],
  "service_path_allow_prefixes": [
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64"
  ],
  "process_allowlist": ["explorer.exe", "svchost.exe", "lsass.exe"],
  "hard_allowlist": ["swprv", "vmservice", "MicrosoftSoftware2ShadowCop4yProvider"],
  "system_process_names": [
    "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "conhost.exe",
    "sihost.exe", "dllhost.exe", "spoolsv.exe", "taskhostw.exe"
  ]
}
```

启动时校验：schema 版本、各数组存在且为字符串数组、`service_interpreter_keywords` **至少含一项**、`service_path_allow_prefixes` **至少含两项**。任一不合法则**拒绝启动并给出明确错误**，不静默降级。

> 为什么给 `service_interpreter_keywords` 加下限：留空数组能通过「是字符串数组」的检查，但会让 `service_interpreter` 判据整体静默失效——界面上表现为「一条可疑服务都没有」，而原因只是有人把数组清空了。这与「绝不用空结果冒充干净」是同一类失败，必须在加载时就拒绝。

`hard_allowlist` 的语义是**只增不减**：引擎在 C++ 内硬编码 `swprv`、`vmservice`、`MicrosoftSoftware2ShadowCop4yProvider` 作为不可下调的地板，配置文件提供的同名数组与之**取并集**。把手工编辑后的 `hard_allowlist` 清空或删项，不会让这三个名字重新变得可报。依据见 §2 硬约束 2。

---

## 9. 报告、日志、CLI、打包

### 9.1 报告

导出 JSON + CSV。

**脱敏**：自动替换本机用户名与机器名为占位符；**文件路径不脱敏**——「这文件到底在哪」是远程判断该不该动手的唯一依据。

### 9.2 日志

每次扫描在 exe 旁写一份，含每条发现、每条错误、提权状态、自检结果。**不做崩溃自动上报**——安全工具向外发数据等于给攻击者留电话。

### 9.3 CLI

GUI 为主，exe 支持 `--scan`（扫描并打印）与 `--json <路径>`（导出 JSON）。输出与 GUI 同源。

### 9.4 打包

便携 zip：`YinHuGuard.exe` + `rules.json` + 依赖 dll（含 `flutter_windows.dll`）+ 首次运行说明（教用户如何在 SmartScreen 放行）。

不做单文件自解压——增签失败与被杀软误报概率上升。一期不签名；二期补 IV 个人代码签名证书（Comodo/Sectigo ≈ $200/年，不需注册公司；Azure Artifact Signing 对中国个人开发者已关闭）。

---

## 10. 目录结构与二期预留

```
<workspace>/YinHuGuard\
  engine/                C++ DLL：全部 Win32 访问
  engine/include/        yh_engine.h（3.1 的接口）
  lib/                   Dart：扫描编排、判据求值、数据模型
  ui/                    Flutter：界面、strings.dart
  rules/rules.json       配置
  fixtures/              合成验证数据
  test/                  判据逻辑单元测试
  bin/                   构建产物
  main                   二期走 feature 分支
```

二期只往 `engine/` 加接口（新增扫描面、清理、回滚），`lib/`、`ui/`、`rules/` 不动。

二期填充 `confidence`、`suggestedAction`、`changeRecord` 三个占位字段。**`changeRecord` 的语义要求：每条发现可追溯到它导致的系统变更**，从而支持逐项回滚。上游 `解禁杀毒软件.bat` 写入 IFEO `Debugger=SYSTEM-RAMOS-ZDY` 后，包内没有任何脚本能清除它——这是必须在一期就占好槽位的理由。

---

## 11. 验证方式及其明确局限

### 11.1 做什么

- 判据逻辑（H/S 属性求值、解释器关键字匹配、路径前缀匹配、白名单折叠、脱敏、CSV 序列化）单元测试
- **合成 fixture** 跑通全流程，确认程序能启动、能出报告。fixture 构造含H/S 属性文件、服务解释器包装、干净负例、以及 `swprv` 硬白名单负例
- 正例（应报）与负例（不应报）双向覆盖

### 11.2 明确不做

**不触碰用户机器**。不建测试环境，不做集成验证，不在用户日常电脑上运行任何东西。交付后由用户自行决定何时运行。

### 11.3 局限（不打折）

合成 fixture 的进程与服务清单**形状由设计者构造**。因此它验证的是判据逻辑与程序可启动性，**不是 Win32 输出格式的解析正确性**。

真机上首次运行时，最可能的失效点是：

- `NtQueryInformationProcess` / `QueryFullProcessImageNameW` 的 FFI 声明与结构体布局
- `EnumServicesStatusExW` 的缓冲区尺寸与 `QueryServiceConfigW` 的两段式调用
- 注册表键遍历的边界情况

这三类错误**编译期不报错、运行时静默返回空**。缓解措施是交付版本把自检按钮放在首屏。

---

## 12. 非目标

明确排除，写在这里以免后续被误加回来：

- ~~**新增扫描面**：驱动服务、计划任务、注册表载荷、文件落点（见 4.6）~~
  —— **2026-10-15 已由二期撤销**，这四个面已实现（见 §13）。其余扫描面
  （Winlogon 劫持、IFEO、WMI 事件订阅、COM/TypeLib 劫持、DLL 侧载、
  企业管控软件寄生）**仍然不做**，理由见 §4.6。
- **进程代码签名校验**（见 4.4）
- 自动修复、隔离区、备份还原
- 驱动 / 内核组件
- 任何形式的代码签名绕过、杀软排除项写入
- `vafdska` / `MiniFilterDrv` / `MicrosoftSoftware2ShadowCop4yProvider` 作为 IOC

---

## 13. 二期变更记录（2026-10-15）

一期交付后按用户要求扩到 **(a) 完整扫描流程** 与 **(b) 深度扫描四面**。三条硬约束
（§2）与「只读」定位**不变**：二期没有引入任何写操作、注入、hook、内存修改或驱动。

### 13.1 (a) 覆盖范围分红/灰 + 提权成为主流程

- `YhSelfCheck` 从 24 字节扩到 **40 字节**，新增四个计数，把「没查到」拆成
  `*_permission`（`OpenProcess` / `OpenServiceW` 被 ACCESS_DENIED 拒）与
  `*_other`（枚举瞬间退出 / 保护进程）。C 侧 20 条 `static_assert` 同步。
- `SelfCheck` 新增 `permissionGaps` / `residualGaps` / `hasPermissionGap` /
  `hasResidual` / `coverageComplete`。
  **分类按提权状态，不按引擎的子分类** —— 未提权时 Session 0 必然整块读不到，
  那是权限问题；已提权时还读不到的是保护进程。把分类权交给引擎，等于允许它的
  误分类把红色警告整个关掉。
- `coverageComplete` 要求**无任何残留**。若不要求，蓝色「覆盖完整」会与列表里
  的红色「N 项未覆盖」同时出现 —— 这是实际发生过的缺陷。
- UI 三态：红色（权限缺口，可行动）/ 灰色（扫描期残留，正常）/ 蓝色（覆盖完整）。
- 「完整扫描（提权重跑）」从警告面板内的补救按钮提为 **AppBar 常驻按钮**。
- 新增 `fixtures/elevated_machine.json`，让「覆盖完整」在 fixture 模式下可达。

### 13.2 (b) 深度扫描四面

新增 `registry_payloads` / `drivers` / `file_drops` / `scheduled_tasks`，
`kSurfaces` 三项 → **七项**，`kCriteria` 三项 → **五项**（新增 `name_match`、
`path_heuristic`），C ABI 从 9 个符号 → **13 个**。

- **威胁名单做成 C++ 里的 source-linked 表**（`engine/include/ioc_table.h`，
  每条带 `evidence_url`），**不放进 `rules.json`**。理由：那不是给用户调的判据
  旋钮，而是从厂商报告正文逐个抄来的事实；混进 config 等于给用户「随手删一条就
  不会再报」的自由度。`rules.json` 的契约因此**保持不变**。
- **计划任务走 Task Scheduler COM（`taskschd.h`）**，不手写 vtable 索引。
  `ITaskFolder` / `IRegisteredTask` 派生自 `IDispatch`，凭记忆抄偏移会导致调用
  错误槽位、表现为「枚举到任务但取不到 action」的静默空结果。用 SDK 头文件后
  偏移由编译器从类型库生成，当场抓出 5 处错误，全部编译期发现。
- `file_drops` 递归设深度与条数上限（**4 层 / 20000 条**），不做全盘扫描。
- 两段式服务枚举抽成 `engine/src/service_enum.cpp` 共享，避免「固定缓冲静默截断
  服务名」出现两份实现。
- 扫描顺序按**耗时递增**排（注册表最快、计划任务最慢），使界面先出结果。
  单次扫描耗时从秒级升到**分钟级**。

### 13.3 二期仍未做

- 清理 / 修复 / 回滚（`changeRecord` 语义见 §10，槽位保留，未填充）
- 进程代码签名校验（§4.4）
- 扫描取消入口
- 真机首跑：**已于 2026-10-15 在本机跑通**（提权 + 非提权各一次，见 §13.4）；
  此前验证覆盖的是编排、判据、分类、报告与界面（§11.3 的局限对二期同样成立）
- 网络 IOC（域名 / IP / URL）

### 13.4 交付后修订（2026-10-16）

用户实测报出两处不一致（均属判定逻辑，不是显示问题），连同补测发现的问题一并修：

- **「已提权仍提示提权」**：已提权后 `ACCESS_DENIED` 只能是系统保护（PPL），
  但列表行、日志原因与徽章仍写「需要以管理员身份重跑才能覆盖」。现在按提权状态
  切换措辞与颜色（徽章「需要提权」→「系统保护」，红 → 中性；日志 flag
  `needs-elevation` → `protected`；侧边栏「未覆盖 N」转中性）。
- **「蓝色覆盖完整 + 红色未覆盖 28 条同屏」**：界面在 `coverageComplete` 之外
  再加一道发现级闸门 `uncoveredCount == 0` —— 自检计数是各面聚合，驱动、注册表
  面没有自检计数，只看聚合数字会漏。
- `SelfCheck` 新增两档判定：`coverageReached`（已提权、权限零缺口 ⇒ 界面常驻
  「已提权：能检查的都已检查」，真机常态）与 `enumerationDead`（进程面或服务面
  为 0 ⇒ 红块「自检异常」，挡住空列表冒充干净）。界面四档互斥：枚举失败 →
  权限缺口 → 覆盖完整 → 已提权。
- **打包防泄漏**：`build_package.ps1` 改白名单复制 + 解压后 `mustExist` /
  `mustNotExist` 校验（上一版 zip 混入 16 个 `reports\` / `$v\` 运行时产物，
  含真实扫描日志与本机路径）。
- 真机首跑（2026-10-15）数据：进程 639–714、服务 361、驱动 492、计划任务 101、
  发现合计 752–842、未覆盖 40（28 系统保护进程 + 12 驱动）、残留 51。