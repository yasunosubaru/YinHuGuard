# YinHuGuard 一期设计规格

- 日期：2026-10-14
- 状态：已与用户确认，待书面复核
- 工作区：`<workspace>/YinHuGuard`
- 上游：`银狐木马处理方案\YinHu病i毒清理脚本（9月27日更新）`（原作者 B 站 @SYSTEM-RAMOS-ZDY）

---

## 1. 定位与范围

单机、只读、离线的银狐（Silver Fox / ValleyRAT 类）持久化**排查工具**。

一期只做检测，不修改系统。目标用户是普通用户，以及远程帮他判断的懂行朋友——因此报告必须可分享、已脱敏、零网络请求。

**一期不做**：清理、修复、回滚；联网更新；崩溃上报；代码签名；注入 / hook / 内存修改 / 驱动编写；安装包。

---

## 2. 三条硬约束

这三条是安全约束，不是偏好，不接受修改。

1. **只走可审计的公开接口。** Win32 访问限于进程查询、SCM 查询、注册表读取、任务计划枚举、文件属性读取。禁止进程注入、API hook、内存读写、驱动加载。原因：清理远控木马的工具如果行为像远控木马，会被 Defender 和第三方杀软优先隔离。
2. **微软系统服务进硬白名单。** 全部系统组件永不参与任何启发式判定。
3. **规则文件是纯数据。** `rules.json` 只含路径 / 文件名 / 服务名 / 任务名 / 注册表键等字符串与出处 URL。程序只解析、只比较，**不执行、不 eval、不加载代码**。更新通道被投毒时的最坏后果因此止于误报或漏报。

---

## 3. 架构

```
Flutter UI (Dart)          单页仪表盘 + 侧边栏落点树
      │  仅通过这一层 FFI 接口 ▼
Scanner Engine (C++ DLL)   全部 Win32 访问收敛于此
      │
      ▼
rules.json (exe 旁)        纯数据规则表
```

选择理由：

- **C++ DLL 而非 Dart 直接声明 FFI**——进程枚举、注册表遍历、任务计划 COM 的结构体与回调很繁杂，散落在 Dart 侧是一堆易错的 ctypes 映射。收敛后改系统 API 只动一个文件。
- **弃用 WMI**——实测本机 690 个进程中，Session 0 的 220 个 `ExecutablePath` **100% 为空**，原脚本的 `ExecutablePath -ne $null` 过滤把银狐最需要藏身的全部系统进程静默丢弃且不报错。改用 `NtQueryInformationProcess` + `QueryFullProcessImageNameW`，服务侧走 `QueryServiceConfigW`。

### 3.1 FFI 边界

按落点类型拆成独立扫描函数，与侧边栏树一一对应，让 UI 能逐类追加结果：

```c
typedef struct {
    char*   locator;              // 注册表路径 / 服务名 / 任务全路径 / 文件完整路径
    char*   display_name;         // 界面展示用
    char*   rule_id;              // 命中的规则 ID
    char*   evidence_url;         // 厂商情报出处，可点击
    char*   criteria;             // "name_match" | "file_attr_hs" | "path_heuristic"
    int32_t attributes_verified;  // 0 = fileAttributes 未知
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
    int32_t windows_temp_readable;
    int32_t services_total;
    int32_t services_with_path;
    int32_t task_count;
} YhSelfCheck;

void*   yh_engine_create(const char* rules_path);
void    yh_engine_destroy(void* h);
int32_t yh_self_check(void* h, YhSelfCheck* out);
int32_t yh_scan_run_keys(void* h, YhFindingList* out);
int32_t yh_scan_services(void* h, YhFindingList* out);
int32_t yh_scan_drivers(void* h, YhFindingList* out);
int32_t yh_scan_scheduled_tasks(void* h, YhFindingList* out);
int32_t yh_scan_registry_payloads(void* h, YhFindingList* out);
int32_t yh_scan_file_drops(void* h, YhFindingList* out);
void    yh_finding_list_free(YhFindingList* l);
void    yh_string_free(char* s);
```

约定：返回 `0` 表示成功，`非0` 为错误码。所有 `char*` 为 UTF-8，由 `yh_string_free` 释放。**每条发现的 `evidence_url` 不得为空**——规则表是从厂商报告正文手工整理的，没有出处就无法复核。

---

## 4. 检测面与判据

### 4.1 一期覆盖的六类落点

均有厂商情报佐证。

| surface | 情报示例 |
|---|---|
| `run_keys` | `HKCU\…\Run` 值 `WINWORD2013` → `C:\Users\WINWORD2013.EXE` |
| `services` | `TCLService`、`svchost.exe -k netcssv` 伪装 |
| `drivers` | `amsdk.sys`、`wamsdk.sys`、`wsftprm.sys`、`BootRepair.sys`、`EnPortv.sys` |
| `scheduled_tasks` | `WindowsPowerShell.WbemScripting.SWbemLocator`、`HandleCommand`、`.NET Framework NGEN vTie` |
| `registry_payloads` | `HKCU\Console\0` 值 `d33f351a4aeea5e608853d1a56661059`、`HKLM\SOFTWARE\IpDates_sun`、标记串 `FaCai2024` |
| `file_drops` | `C:\Windows\Temp\aceprocted.sys`、`ranchserv.jpg`、`C:\ProgramData\*.sys`、`C:\Users\Public\Documents\WindowsData\`、`C:\Program Files\Internet Explorer\<6位随机>\QduoQFO.exe` |

### 4.2 三类判据并存

单一判据覆盖不了三类不同对象——这正是原脚本的病根（只有 H/S 属性，所以只能查文件，一查服务就抓瞎）。

1. **`name_match`**——名单匹配，**命中即报，不查属性**。银狐已知落点躺在 `C:\Windows\Temp\` 里是明文可见的，不靠隐藏属性。
2. **`file_attr_hs`**——仅对真实存在的文件，沿用原脚本的 `H`/`S` 属性判定（`findstr /i "h s"` 的语义）。
3. **`path_heuristic`**——路径合理性。判据**硬编码在 C++ 里**（数量少、需版本管理），不进 `rules.json`。

`path_heuristic` 固定集合：

- 驱动服务 `ImagePath` 落在 `C:\Windows\System32\drivers\` 之外
- 服务 `ImagePath` 使用 `cmd /c`、`powershell`、`wscript`、`cscript`、`mshta`、`pwsh` 包装（原脚本的解释器关键字集，保留）
- 计划任务 action 路径不在任务 XML 声明目录内

### 4.3 文件落点用完整路径匹配

情报里的落点文件名多为 6 位随机字母数字（`QduoQFO`、`aceprocted`），单文件名匹配会在任何路径大量误报。**必须完整路径匹配。**

### 4.4 进程白名单靠代码签名兜底

情报指出银狐专门注入 `svchost` / `vssvc` / `explorer` / `winlogon`，且样本逻辑是「目标进程名已是这些则跳过注入」——**进程名无法区分正常与被注入**。

因此进程白名单附加**代码签名校验**：签名有效且签名人属 `trusted_signers` 才算白；签名缺失或签名者陌生，进程名再眼熟也照报。签名者列表来自 `rules.json` 的 `trusted_signers`，默认含 `Microsoft Corporation`。

### 4.5 明确排除（二期有银狐实证再补）

Winlogon 劫持、IFEO 映像劫持、WMI 事件订阅、COM/TypeLib 劫持、企业管控软件寄生、DLL 侧载。

理由：情报未找到银狐实际使用这些手法的公开证据。作为通用后门手法放进默认规则只会产生噪音。

### 4.6 硬白名单

以下永不参与任何判定：

- **全部微软系统服务**，含 `swprv`
- `vmservice`
- `MicrosoftSoftware2ShadowCop4yProvider` — 情报确认这是 `swprv`（Microsoft Software Shadow Copy Provider）的微软**数字混淆显示名**。上游 `解禁杀毒软件.bat` 把它当银狐驱动 `reg delete`，等于抹掉 Windows 卷影复制服务。
- `vafdska`、`MiniFilterDrv` — 情报未找到任何银狐出处，作民间脚本产物处理，不作 IOC

---

## 5. 数据模型

```dart
class Finding {
  final String surface;          // 见 4.1 的六个值
  final String locator;          // 完整定位符
  final String displayName;
  final String? ruleId;
  final String? evidenceUrl;     // 必填，见 3.1
  final String criteria;         // name_match | file_attr_hs | path_heuristic
  final bool attributesVerified;
  final bool hidden;
  final bool system;
  final bool elevationRequired;
  final bool covered;            // false = 权限不足未覆盖
  final DateTime timestamp;

  // 以下为一期占位，二期填充（见第 10 节）
  final double? confidence;
  final SuggestedAction? suggestedAction;
  final ChangeRecord? changeRecord;
}
```

`covered: false` 是**强制语义**：该项因权限不足未检查，UI 必须明示「未覆盖」，绝不能用空结果冒充「干净」。上游脚本的 `2^>nul` 正是这个错误。

---

## 6. 权限模型

- 只读扫描**免提权**启动
- 需要提权的项（`C:\Windows\Temp`、Session 0 进程路径）用 `ShellExecuteEx` + `runas` **逐项**弹 UAC
- 不做「一运行就 UAC」——只读扫描拿管理员权限没有正当理由，却让用户第一眼就怀疑这是恶意软件

实测基线（本机，用户态）：服务 360 个 / 358 个有 `PathName`，全可读；计划任务 219 个可见；`C:\Windows\Temp` **拒绝访问**；Session 0 进程路径 100% 不可读。

---

## 7. UI

- **单页仪表盘，打开即扫**，进度条 + 结果实时追加，底部固定导出按钮。不做引导式向导
- **侧边栏六项落点树**（对应 4.1 的六个 `surface`）用于**切换查看**，不用于控制扫不扫
- 表格**默认按落点类型分组、组内时间倒序**
- **首屏放自检按钮**：实测并显示 Session 0 进程数、`Windows\Temp` 可达性、服务 `PathName` 覆盖率、是否已提权
- 因 Q2 决定「照搬原脚本只看 H/S」，一期不渲染颜色分级，分组是唯一的快速扫读结构
- 文案走手写 `strings.dart` 字典（二期换 `gen-l10n` 只差换文件）
- 产品界面为中文，二期补英文

---

## 8. 规则表 `rules.json`

外置在 exe 旁边，手工编辑、可复制传阅。程序零网络请求。

```json
{
  "schema_version": 1,
  "updated_at": "2026-10-14",
  "hard_allowlist": ["swprv", "vmservice", "MicrosoftSoftware2ShadowCop4yProvider"],
  "trusted_signers": ["Microsoft Corporation"],
  "rules": [
    {
      "id": "svc-clever_soar",
      "surface": "services",
      "match": "exact",
      "value": "CleverSoar",
      "field": "name",
      "evidence_url": "https://…",
      "note": "银狐 Winos loader 拉起的真实服务"
    },
    {
      "id": "task-wbemlocator",
      "surface": "scheduled_tasks",
      "match": "exact",
      "value": "\\WindowsPowerShell.WbemScripting.SWbemLocator",
      "field": "task_path",
      "evidence_url": "https://www.nextron-systems.com/…",
      "note": "Nextron 报告的伪装任务名"
    }
  ]
}
```

- `surface`：4.1 的六个值之一
- `match`：`exact` | `prefix` | `suffix` | `glob` | `regex`
- `field`：`name` | `display_name` | `image_path` | `task_path` | `action_path` | `registry_path` | `file_path` | `file_name`
- `evidence_url`：**必填且必须是 http(s)**

启动时校验：schema 版本、`evidence_url` 存在性、`surface` 与 `field` 的合法组合。任一不合法则**拒绝启动并给出明确错误**，不静默降级。

---

## 9. 报告、日志、CLI、打包

### 9.1 报告

导出 JSON + CSV。

**脱敏**：自动替换本机用户名与机器名为占位符；**文件路径不脱敏**——「这文件到底在哪」是远程判断该不该动手的唯一依据。

### 9.2 日志

每次扫描在 exe 旁写一份，含每条发现、每条错误、提权状态、自检结果。**不做崩溃自动上报**——安全工具向外发数据等于给攻击者留电话。

### 9.3 CLI

GUI 为主，exe 支持 `--scan`（扫描并打印）与 `--json <路径>`（导出 JSON）。输出与 GUI 同源。方便在没有 GUI 环境的机器上取证。

### 9.4 打包

便携 zip：`YinHuGuard.exe` + `rules.json` + 依赖 dll（含 `flutter_windows.dll`）+ 首次运行说明（教用户如何在 SmartScreen 放行）。

不做单文件自解压——增签失败与被杀软误报概率上升。一期不签名；二期补 IV 个人代码签名证书（Comodo/Sectigo ≈ $200/年，不需注册公司；Azure Artifact Signing 对中国个人开发者已关闭）。

---

## 10. 目录结构与二期预留

```
<workspace>/YinHuGuard\
  engine/            C++ DLL：全部 Win32 访问
  engine/include/    yh_engine.h（3.1 的接口）
  lib/               Dart：扫描编排、判据求值、数据模型
  ui/                Flutter：界面、strings.dart
  rules/rules.json   规则表
  fixtures/          合成验证数据
  test/              判据逻辑单元测试
  bin/               构建产物
  main               二期走 feature 分支
```

二期只往 `engine/` 加接口（清理、回滚），`lib/`、`ui/`、`rules/` 不动。这是选 C++ DLL 收敛边界的回报。

二期填充 `confidence`、`suggestedAction`、`changeRecord` 三个占位字段。**`changeRecord` 的语义要求：每条发现可追溯到它导致的系统变更**，从而支持逐项回滚。上游 `解禁杀毒软件.bat` 写入 IFEO `Debugger=SYSTEM-RAMOS-ZDY` 后，包内没有任何脚本能清除它——这是必须在一期就占好槽位的理由。

---

## 11. 验证方式及其明确局限

### 11.1 做什么

- 判据逻辑（路径合理性求值、名单匹配、规则解析、脱敏、CSV 序列化）单元测试
- **合成 fixture** 跑通全流程，确认程序能启动、能出报告。fixture 按厂商 IOC 构造，含真实的服务名 / 任务名 / 注册表键 / 完整文件路径
- 覆盖正例（应报）与负例（不应报，含 `swprv` 硬白名单负例）

### 11.2 明确不做

**不触碰用户机器**。不建测试环境，不做集成验证，不在用户日常电脑上运行任何东西。交付后由用户自行决定何时运行。

### 11.3 局限（不打折）

合成 fixture 的进程与服务清单**形状由设计者构造**。因此它验证的是判据逻辑与程序可启动性，**不是 Win32 输出格式的解析正确性**。

真机上首次运行时，最可能的失效点是：

- `QueryFullProcessImageNameW` 的 FFI 声明与结构体布局
- 任务计划 COM 接口的签名
- 注册表遍历的边界情况

这三类错误**编译期不报错、运行时静默返回空**。缓解措施是交付版本把自检按钮放在首屏。

---

## 12. 非目标

以下明确排除，写在这里以免后续被误加回来：

- 自动修复、隔离区、备份还原
- 驱动 / 内核组件
- 任何形式的代码签名绕过、杀软排除项写入
- `vafdska` / `MiniFilterDrv` / `MicrosoftSoftware2ShadowCop4yProvider` 作为 IOC
- 网络 IOC（域名 / IP / URL）—— abuse.ch 有，但那是另一类工具的职责