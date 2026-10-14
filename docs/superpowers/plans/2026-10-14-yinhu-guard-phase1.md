# YinHuGuard 一期 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一个 Windows 桌面只读排查工具，忠实重建上游 `查找隐藏的进程和启动项.bat` 的三段核心扫描（隐藏进程 / 隐藏启动项 / 可疑服务），修掉已确认的实现缺陷，打包为免安装便携 zip。

**Architecture:** Flutter UI + Dart 判据层 + C++ DLL Win32 访问层。Win32 调用全部收敛进一个 C++ DLL，Dart 侧只经一层扁平 FFI 接口取「观测」；判据求值、白名单折叠、脱敏、报告全在 Dart 侧，因此可脱离 Flutter 用纯 Dart 单测覆盖。观测来源被抽象为接口，使同一套编排与报告逻辑既能跑真实 Win32，也能跑合成 fixture。

**Tech Stack:** C++17 / CMake / Win32 API（`NtQueryInformationProcess`、`QueryFullProcessImageNameW`、`EnumServicesStatusExW`、`QueryServiceConfigW`、Reg API）/ Dart 3 / Flutter（Windows desktop）/ `dart:ffi` / `package:test`

**Spec:** `docs/superpowers/specs/2026-10-14-yinhu-guard-design.md`

## Global Constraints

以下每一条都适用于全部任务，逐字取自 spec：

- **目标平台**：仅 Windows x64。不做 32 位，不做 ARM，不做跨平台。
- **禁用 WMI**。进程路径一律走 `NtQueryInformationProcess` + `QueryFullProcessImageNameW`；服务一律走 `EnumServicesStatusExW` + `QueryServiceConfigW`。理由见 spec §3：实测 Session 0 的 220 个进程 `ExecutablePath` 100% 为空。
- **禁止**进程注入、API hook、内存读写、驱动加载。Win32 访问限于：进程查询、进程主模块签名查询（本期不实现）、SCM 查询、注册表读取、文件属性读取。
- **解释器关键字集合固定**，一个不加一个不减：`["cmd /c", "powershell", "wscript", "cscript", "mshta", "pwsh"]`
- **服务路径白名单前缀固定**：`["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"]`
- **硬白名单**（永不参与任何判定，含 `swprv`、`vmservice`、`MicrosoftSoftware2ShadowCop4yProvider`）。**`vafdska` 与 `MiniFilterDrv` 不得作为 IOC。**
- **配置文件是纯数据**，程序只解析、只比较，**不执行、不 eval、不加载代码**。配置校验失败必须**拒绝启动并给出明确错误**，不得静默降级。
- **`covered=false` 是强制语义**：该项因权限不足未检查。UI 必须明示「未覆盖」。**绝不能用空结果冒充「干净」。** 上游 `2^>nul` 正是这个错误。
- **脱敏**：自动把本机用户名与机器名替换为 `<USER>` 与 `<MACHINE>`；**文件路径不脱敏**。
- **不做崩溃自动上报。**
- **一期不签名。** 不做单文件自解压打包。
- **不做进程代码签名校验**（spec §4.4，移出一期）。一期只有 `rules.json` 的用户白名单，无签名查询。
- **不新增扫描面**：驱动服务、计划任务、注册表载荷、文件落点一律不做（spec §4.6）。`engine/` 中不得出现这四类的枚举代码。
- **严禁在开发机上执行任何枚举真实系统的代码路径。** 允许：编译、链接、导出表检查、纯函数单元测试、跑 fixture。禁止：启动 GUI 真实扫描、运行不带 `--fixture` 的 `--scan`、调用 `yh_scan_*`、运行 `yh_self_check`、触发 UAC 提权。理由见 spec §11.2–11.3 与用户明确约束「严格不能在我的电脑测试」。

## Review Focus

spec 隐含、但任何任务的测试都不会自然覆盖的五类输入／失效模式，按「最可能咬到使用者」排序。每个后面标注由哪个任务负责固定住。

1. **无提权时 Session 0 进程路径不可读** —— 表现必须是「N 个未覆盖」且自检计数里 `session0_visible` 明确为 0，**绝不能**收敛成「0 个可疑进程，机器干净」这种结论。用户判断依据是这条结论，不是有没有弹 UAC。（Task 2、Task 5）
2. **`REG_EXPAND_SZ` 值里含环境变量**（如 `%TEMP%\x.exe`）—— 上游 bat 用 cmd `if exist` 判定，而 cmd **不展开注册表 `REG_EXPAND_SZ`**，所以上游对这些值一律误判为「不存在」而漏报。本项目必须先展开再判存在。（Task 1、Task 3）
3. **中文与非 ASCII 路径** —— 银狐用 6 位随机名与乱码名落点，用户机器路径大量含中文。FFI 两侧 UTF-8↔UTF-16 转换错一个字符，`locator` 就是乱码，报告直接失去价值。（Task 1、Task 4）
4. **服务 `ImagePath` 带引号和参数**（`"C:\path\sv.exe" -k netsvcs`）—— 关键字匹配必须仍能命中，路径前缀判定必须先剥引号与参数，否则每个带参数的服务都会被 `service_path_heuristic` 误报。（Task 1、Task 3）
5. **`REG_SZ` 值数据形态多样** —— 无引号整串、单个引号、`%VAR%` 前缀、`\systray32\foo.exe` 形式。上游用「取引号内内容，取不到就取整串，再剥尾随 `)`」三层回退。这套回退必须逐条复刻，否则解析出错误路径。（Task 1）

---

### Task 1: C++ 引擎骨架与纯判据函数

**Files:**
- Create: `engine/CMakeLists.txt`
- Create: `engine/include/yh_engine.h`
- Create: `engine/include/yh_criteria.h`
- Create: `engine/src/criteria.cpp`
- Create: `engine/src/config.cpp`
- Test: `engine/tests/test_criteria.cpp`

**Interfaces:**
- Consumes: 无（首个任务）
- Produces:
  ```cpp
  // engine/include/yh_criteria.h
  namespace yh {
    // 等价上游 findstr /i "h s"：FILE_ATTRIBUTE_HIDDEN(0x2) 或 FILE_ATTRIBUTE_SYSTEM(0x4)
    bool has_hidden_or_system(uint32_t file_attributes);

    // 上游 :ScanRun 的值数据解析回退链，完整复刻
    std::string extract_run_value_path(const std::string& reg_value_data);

    // 展开 %VAR% 与 %VAR%（未知变量保持原样，不报错）
    std::string expand_env_vars(const std::string& path, bool* expanded_ok);

    // 剥掉首尾引号与第一个参数段："C:\a\b.exe" -k netsvcs -> C:\a\b.exe
    std::string strip_quotes_and_args(const std::string& image_path);

    // 解释器关键字匹配，大小写不敏感；keywords 为固定六元集合
    bool matches_interpreter(const std::string& image_path,
                             const std::vector<std::string>& keywords);

    // 路径前缀判定，大小写不敏感，边界必须是目录分隔符
    bool path_in_prefixes(const std::string& image_path,
                          const std::vector<std::string>& prefixes);

    // 硬白名单 + 用户白名单。命中返回 true → 该条目不产生发现
    bool is_hard_allowlisted(const std::string& name,
                             const std::vector<std::string>& hard_allowlist);
  }
  ```

- [ ] **Step 1: 写失败测试 `engine/tests/test_criteria.cpp`**

  固定 spec §8 的六个关键字与两个前缀。每个用例单独命名，断言写死：

  ```cpp
  // 解释器关键字：spec §8 固定六元集合，逐个正例 + 三个负例
  std::vector<std::string> kw = {"cmd /c", "powershell", "wscript",
                                 "cscript", "mshta", "pwsh"};
  assert(matches_interpreter("C:\\Windows\\System32\\cmd.exe /c foo.bat", kw)); // cmd /c
  assert(matches_interpreter("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc AAAA", kw));
  assert(matches_interpreter("C:\\Windows\\System32\\wscript.exe C:\\a\\b.vbs", kw));
  assert(matches_interpreter("C:\\Windows\\System32\\cscript.exe C:\\a\\b.js", kw));
  assert(matches_interpreter("C:\\Windows\\mshta.exe http://x", kw));
  assert(matches_interpreter("C:\\Program Files\\PowerShell\\7\\pwsh.dll", kw));
  assert(!matches_interpreter("C:\\Windows\\System32\\svchost.exe -k netsvcs", kw));
  assert(!matches_interpreter("C:\\Windows\\System32\\services.exe", kw));
  assert(!matches_interpreter("C:\\Windows\\System32\\cmd.exe", kw));  // 无 "/c" 不命中

  // Review Focus #4：带引号带参数仍要命中，且剥出干净路径
  assert(strip_quotes_and_args("\"C:\\a\\sv.exe\" -k netsvcs") == "C:\\a\\sv.exe");
  assert(strip_quotes_and_args("C:\\a\\sv.exe -k netsvcs") == "C:\\a\\sv.exe");
  assert(matches_interpreter("\"C:\\a\\cmd.exe\" /c x.bat", kw));

  // Review Focus #5：Run 值数据回退链
  assert(extract_run_value_path("\"C:\\a\\b.exe\" -s") == "C:\\a\\b.exe");
  assert(extract_run_value_path("C:\\a\\b.exe") == "C:\\a\\b.exe");
  assert(extract_run_value_path("\"%TEMP%\\x.exe\"") == "%TEMP%\\x.exe");
  assert(extract_run_value_path("C:\\a\\b.exe\")") == "C:\\a\\b.exe");   // 剥尾随 ')'
  assert(extract_run_value_path("") == "");

  // Review Focus #2：REG_EXPAND_SZ 的 %VAR% 必须先展开再判存在
  bool ok = false;
  assert(expand_env_vars("C:\\Windows\\Temp\\x.exe", &ok) == "C:\\Windows\\Temp\\x.exe");
  assert(expand_env_vars("%TEMP%\\x.exe", &ok) == std::string(getenv("TEMP")) + "\\x.exe");
  assert(ok);
  assert(expand_env_vars("%NOSUCHVAR_XYZ%\\x.exe", &ok) == "%NOSUCHVAR_XYZ%\\x.exe");
  assert(!ok);   // 未知变量保持原样并标记未完全展开

  // H/S 属性：spec §4.1 唯一判据
  assert(has_hidden_or_system(0x2));            // HIDDEN
  assert(has_hidden_or_system(0x4));            // SYSTEM
  assert(has_hidden_or_system(0x6));            // HIDDEN|SYSTEM
  assert(has_hidden_or_system(0x20));           // ARCHIVE
  assert(has_hidden_or_system(0x20 | 0x1));     // ARCHIVE|READONLY
  assert(!has_hidden_or_system(0x0));

  // 路径前缀：边界必须是目录分隔符
  std::vector<std::string> pre = {"C:\\Windows\\System32", "C:\\Windows\\SysWOW64"};
  assert(path_in_prefixes("C:\\Windows\\System32\\svchost.exe", pre));
  assert(path_in_prefixes("C:\\Windows\\SysWOW64\\cmd.exe", pre));
  assert(!path_in_prefixes("C:\\Windows\\System32X\\evil.exe", pre));  // 前缀误配
  assert(!path_in_prefixes("C:\\Users\\Public\\x.exe", pre));
  assert(path_in_prefixes("c:\\windows\\system32\\svchost.exe", pre)); // 大小写不敏感

  // 硬白名单：swprv 必须在
  std::vector<std::string> hard = {"swprv", "vmservice",
                                   "MicrosoftSoftware2ShadowCop4yProvider"};
  assert(is_hard_allowlisted("swprv", hard));
  assert(is_hard_allowlisted("MicrosoftSoftware2ShadowCop4yProvider", hard));
  assert(!is_hard_allowlisted("CleverSoar", hard));
  // vafdska / MiniFilterDrv 不是白名单项，也绝不能出现在配置里
  assert(!is_hard_allowlisted("vafdska", hard));
  ```

- [ ] **Step 2: 编译并运行测试，确认失败**

  ```
  cmake -S engine -B engine/build -A x64
  cmake --build engine/build --config Release
  engine\build\Release\test_criteria.exe
  ```
  Expected: **配置阶段**即失败——`engine/CMakeLists.txt` 尚不存在（它在 Step 5 创建）。这是一个退化的 RED：验证的是「构建系统还没搭好」，不是「判据函数未实现」。真正的函数级 RED 在 Step 6 之后首次成功链接时由 `test_criteria.cpp` 里的断言承担。

- [ ] **Step 3: 创建 `engine/include/yh_criteria.h`**，照 Step 1 的 Interfaces 块逐字声明七个函数，全部 `namespace yh`、`std::string`/`std::vector<std::string>` 参数显式带类型。

- [ ] **Step 4: 实现 `engine/src/criteria.cpp`**

  需要注意的算法点（其余由签名与测试决定，不写函数体）：

  - `has_hidden_or_system`：`(attrs & 0x6) != 0`
  - `extract_run_value_path`：复刻上游三层回退——先找首个 `"` 到末个 `"` 之间的内容；找不到引号则取整个值；最后若以 `)` 结尾则剥掉。空输入返回空串。**Review Focus #5 的四个断言就是这三层的行为契约，不得改写为「只取引号内」。**
  - `expand_env_vars`：用 `ExpandEnvironmentStringsW`。用 `GetFileName` 无意义。调用前先用 `GetEnvironmentVariableW` 探测是否存在未知变量；存在未知变量则置 `*expanded_ok = false` 但仍返回尽力展开后的字符串。缓冲区两段式（先返回长度再分配），不要用固定大小缓冲。
  - `strip_quotes_and_args`：先剥首尾 `"`，若原串以 `"` 开头，则在闭合引号之后截断（丢弃 `-k netsvcs` 这类参数）；若不以引号开头，取第一个空格前的部分。
  - `matches_interpreter`：对 `image_path` 与每个关键字做子串查找，转小写后比较。**不要**先剥参数——上游就是对整行 `ImagePath` 做 `findstr`，含 `"C:\a\cmd.exe" /c x.bat` 这类也要能命中。
  - `path_in_prefixes`：先 `strip_quotes_and_args`，再大小写不敏感比较，且要求第 N 位是 `\` 或 `/`，避免 `System32X` 误配。
  - `is_hard_allowlisted`：大小写不敏感全等比较，不做子串匹配。

- [ ] **Step 5: 创建 `engine/CMakeLists.txt`、`engine/src/config.cpp`，以及 `engine/include/yh_engine.h` 的最小骨架**

  **`engine/CMakeLists.txt`** 必须做到：设 C++17、项目名 `yinhuguard_engine`、产出共享库 `yinhuguard_engine`、导出符号不被剔除（Linux 上是 `WINDOWS_EXPORT_ALL_SYMBOLS` 之类的等效设置，Windows 上默认全导出）、`include/` 为 PUBLIC include 目录、把 `src/*.cpp` 全部纳入、注册 `test_criteria` 可执行目标并链上 `src/criteria.cpp` 与 `src/config.cpp`。目标平台 x64。

  **`yh_engine.h`** 先只声明 Task 1 用得到的部分：`namespace yh { struct Config; std::unique_ptr<Config> load_config(const std::string& path, std::string* error); }`。

  **`load_config`** 实现 spec §8 的校验规则。此处**不做 JSON 解析库选型**，改用最轻量方案：配置是扁平字符串数组，`rules.json` 用固定顺序的数组结构，逐个读入并校验「每项必须是字符串」。校验失败时 `*error` 写入**具体是哪个键不合法**，返回 `nullptr`。

- [ ] **Step 6: 运行测试，确认通过**

  ```
  cmake --build engine/build --config Release
  engine\build\Release\test_criteria.exe
  ```
  Expected: 全部断言通过，进程退出码 0。

- [ ] **Step 7: Commit**

  ```bash
  git add engine/
  git commit -m "feat(engine): 判据纯函数与配置校验，含 Review Focus 2/4/5 用例"
  ```

---

### Task 2: Dart 数据模型、判据求值与脱敏

**Files:**
- Create: `pubspec.yaml`
- Create: `lib/src/model/observation.dart`
- Create: `lib/src/model/finding.dart`
- Create: `lib/src/model/self_check.dart`
- Create: `lib/src/criteria/evaluator.dart`
- Create: `lib/src/criteria/redact.dart`
- Test: `test/evaluator_test.dart`
- Test: `test/redact_test.dart`

**Interfaces:**
- Consumes: 无（纯 Dart，不依赖 Flutter，不依赖 engine）
- Produces:
  ```dart
  // lib/src/model/observation.dart —— 与 FFI 的 YhFinding 一一对应
  class Observation {
    final String surface;          // 严格三值之一
    final String locator;
    final String displayName;
    final String criteria;         // 严格三值之一
    final bool attributesVerified;
    final bool hidden;
    final bool system;
    final bool elevationRequired;
    final bool covered;            // false = 未覆盖
    final DateTime timestamp;
  }

  // lib/src/model/finding.dart —— Observation + 白名单折叠结果
  class Finding {
    final Observation observation;
    final bool allowlisted;
    final double? confidence;      // 一期恒 null
    final String? suggestedAction; // 一期恒 null
    final String? changeRecord;    // 一期恒 null
    bool get attributesVerified => observation.attributesVerified;
    bool get covered => observation.covered;
    String get surface => observation.surface;
    String get locator => observation.locator;
  }

  // lib/src/model/self_check.dart
  class SelfCheck {
    final bool elevated;
    final int processTotal;
    final int processPathResolved;
    final int session0Visible;     // 非提权时为 0 —— Review Focus #1
    final int servicesTotal;
    final int servicesWithPath;
  }

  // lib/src/criteria/evaluator.dart
  const kSurfaces = <String>['processes', 'run_keys', 'services'];
  const kCriteria = <String>['file_attr_hs', 'service_interpreter', 'service_path_heuristic'];

  List<Finding> evaluate(
    List<Observation> observations, {
    required List<String> userAllowlist,
  });

  // lib/src/criteria/redact.dart
  String redactPath(String raw, {required String username, required String machineName});
  ```

- [ ] **Step 1: 写失败测试 `test/evaluator_test.dart`**

  ```dart
  test('surface 与 criteria 只接受 spec 规定的三值', () {
    expect(kSurfaces, ['processes', 'run_keys', 'services']);
    expect(kCriteria, ['file_attr_hs', 'service_interpreter', 'service_path_heuristic']);
  });

  test('covered=false 的观测原样保留,不被白名单折叠,也不被丢弃', () {
    final obs = Observation(
      surface: 'processes', locator: r'C:\a\b.exe', displayName: 'b.exe',
      criteria: 'file_attr_hs', attributesVerified: true, hidden: true,
      system: false, elevationRequired: true, covered: false,
      timestamp: DateTime.utc(2026, 10, 14));
    final out = evaluate([obs], userAllowlist: ['b.exe']);
    expect(out, hasLength(1));
    expect(out.single.covered, isFalse);
    expect(out.single.allowlisted, isFalse);   // 未覆盖项不能算白名单命中
  });

  test('用户白名单折叠为 allowlisted=true 但保留条目', () {
    // ... 同上构造 covered: true, userAllowlist: ['b.exe']
    final out = evaluate([obs], userAllowlist: ['b.exe']);
    expect(out.single.allowlisted, isTrue);
    expect(out.single.locator, r'C:\a\b.exe');
  });

  test('白名单只按 basename 匹配,不按完整路径', () {
    // locator = r'C:\Users\me\AppData\Local\b.exe', allowlist ['b.exe'] -> allowlisted true
  });

  test('三个占位字段一期恒为 null', () {
    final out = evaluate([obs], userAllowlist: const []);
    expect(out.single.confidence, isNull);
    expect(out.single.suggestedAction, isNull);
    expect(out.single.changeRecord, isNull);
  });
  ```

- [ ] **Step 2: 写失败测试 `test/redact_test.dart`**

  ```dart
  test('用户名被替换为 <USER>,机器名被替换为 <MACHINE>', () {
    expect(
      redactPath(r'C:\Users\zhangwei\AppData\Local\a.exe',
                 username: 'zhangwei', machineName: 'TEST-PC'),
      r'C:\Users\<USER>\AppData\Local\a.exe');
  });

  test('机器名出现在路径任意位置都被替换', () {
    expect(
      redactPath(r'\\TEST-PC\share\a.exe',
                 username: 'zhangwei', machineName: 'TEST-PC'),
      r'\\<MACHINE>\share\a.exe');
  });

  test('路径其余部分原样保留 —— 不脱敏路径是 spec §9.1 硬要求', () {
    expect(
      redactPath(r'C:\Program Files\Internet Explorer\Ab3xY9\QduoQFO.exe',
                 username: 'zhangwei', machineName: 'PC'),
      r'C:\Program Files\Internet Explorer\Ab3xY9\QduoQFO.exe');
  });

  test('大小写不敏感替换', () {
    expect(
      redactPath(r'C:\Users\ZhangWei\a.exe', username: 'zhangwei', machineName: 'PC'),
      r'C:\Users\<USER>\a.exe');
  });

  test('空用户名或机器名时不产生空占位符', () {
    expect(redactPath(r'C:\a\b.exe', username: '', machineName: ''), r'C:\a\b.exe');
  });
  ```

- [ ] **Step 3: 运行测试，确认失败**

  ```
  dart test
  ```
  Expected: 失败，`Observation` 未定义。

- [ ] **Step 4: 创建 `pubspec.yaml`**

  ```yaml
  name: yinhuguard
  environment:
    sdk: '>=3.4.0 <4.0.0'
  dev_dependencies:
    test: ^1.25.0
  ```
  `lib/src/**` 全部保持纯 Dart，不引入 `flutter` 依赖——这样 Task 2–6 的测试不需要 Flutter SDK。

- [ ] **Step 5: 创建三个 model 文件**，照 Interfaces 块的字段名与类型逐字定义。`Observation` 加 `assert(kSurfaces.contains(surface))` 与 `assert(kCriteria.contains(criteria))` 构造期校验。**不要**给 `Finding` 加 Task 2 用不到的字段。

- [ ] **Step 6: 实现 `lib/src/criteria/evaluator.dart`**

  `evaluate` 只做三件事：构造 `Finding`、计算 `allowlisted`（**仅当 `covered == true` 时**才可能为 true）、保持顺序不变。不做排序——分组排序在 Task 7 的 UI 层做。不做去重——去重属于观测来源，去重策略在 Task 3 落地。

- [ ] **Step 7: 实现 `lib/src/criteria/redact.dart`**

  先按 `machineName` 替换，再按 `username` 替换。两者任一为空字符串则跳过该次替换（Review Focus 用例 5）。替换大小写不敏感。**不做任何路径规范化**——`Program Files` 里的空格原样保留。

- [ ] **Step 8: 运行测试，确认通过**

  ```
  dart test
  ```
  Expected: 全绿。

- [ ] **Step 9: Commit**

  ```bash
  git add pubspec.yaml lib/ test/
  git commit -m "feat(lib): 数据模型、判据求值与脱敏（纯 Dart，无 Flutter 依赖）"
  ```

---

### Task 3: C++ 引擎真实系统枚举（编译与导出验证，不执行）

**Files:**
- Create: `engine/src/processes.cpp`
- Create: `engine/src/run_keys.cpp`
- Create: `engine/src/services.cpp`
- Create: `engine/src/self_check.cpp`
- Create: `engine/src/engine.cpp`
- Modify: `engine/include/yh_engine.h`（补齐 spec §3.1 全部符号）
- Test: `engine/tests/test_config.cpp`

**Interfaces:**
- Consumes: Task 1 的 `yh::` 判据函数、`yh::load_config`
- Produces: spec §3.1 全部导出符号，签名逐字照抄：
  ```cpp
  extern "C" {
    void*   yh_engine_create(const char* config_path);
    void    yh_engine_destroy(void* h);
    int32_t yh_self_check(void* h, YhSelfCheck* out);
    int32_t yh_scan_processes(void* h, YhFindingList* out);
    int32_t yh_scan_run_keys(void* h, YhFindingList* out);
    int32_t yh_scan_services(void* h, YhFindingList* out);
    void    yh_finding_list_free(YhFindingList* list);
    void    yh_string_free(char* s);
  }
  ```
  返回码：`0` = OK，`1` = 配置无效，`2` = 分配失败。

- [ ] **Step 1: 写失败测试 `engine/tests/test_config.cpp`**

  只测配置校验（纯逻辑，不触碰真实系统）：合法的 `rules.json` 样本加载成功；缺 `service_interpreter_keywords` 失败且 `error` 含该键名；`service_path_allow_prefixes` 只有一项时失败（spec §8 要求至少两项）；未知 `schema_version` 失败。四个用例均只操作**临时目录里的测试用 json 文件**。

- [ ] **Step 2: 编译运行，确认失败**

  ```
  cmake --build engine/build --config Release
  engine\build\Release\test_config.exe
  ```
  Expected: 编译失败，`yh_engine.h` 缺少 `yh_scan_*` 声明。

- [ ] **Step 3: 补齐 `engine/include/yh_engine.h`**

  照 spec §3.1 逐字加入 `YhFinding`、`YhFindingList`、`YhSelfCheck` 三个 POD 结构与八个 `extern "C"` 声明。结构体字段顺序与 spec 完全一致——Dart 侧按位置读，顺序错了不会编译报错，只会读出垃圾。

- [ ] **Step 4: 实现 `engine/src/processes.cpp`**

  `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` 枚举 → 对每个 PID `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → `NtQueryInformationProcess` 取 `PROCESS_BASIC_INFORMATION` 得 `PEB` → 从 PEB 取 `ProcessParameters` → `RTL_USER_PROCESS_PARAMETERS.ImagePathName`（UNICODE_STRING）→ `QueryFullProcessImageNameW` 作为更稳的备选。

  关键点：
  - **`OpenProcess` 返回 `NULL` 时不要跳过**。置 `covered = false`、`elevation_required = true`、写入一条 `attributesVerified=false` 的 `Observation`。这正是 Review Focus #1——Session 0 进程在非提权下全部走这条路径，**它们的可见性必须在自检计数里体现为 `session0_visible`，而不是消失**。
  - 判据用 Task 1 的 `has_hidden_or_system(GetFileAttributesW(path))`。`GetFileAttributesW` 返回 `INVALID_FILE_ATTRIBUTES` 时置 `attributesVerified = false`，**不产生发现也不隐藏存在性**。
  - 按 `locator` 去重（上游 `Sort-Object -Unique` 的等价物），**用不区分大小写的比较**。
  - 所有 `char*` 用 `yh_string_free` 可释放的分配器（即 `malloc` 或与其配对的实现）。

- [ ] **Step 5: 实现 `engine/src/run_keys.cpp`**

  遍历 spec §4.2 的三个键。对每个值的 `REG_SZ` 与 `REG_EXPAND_SZ`：取数据 → `yh::extract_run_value_path` → `yh::expand_env_vars` → 若 `expand_env_vars` 的 `expanded_ok == false`，记 `covered = false`（**Review Focus #2**：环境变量未展开就无法判断文件是否存在，必须显式标未覆盖，不能当不存在）→ `GetFileAttributesW` 判存在 → `has_hidden_or_system`。
  
  **上游 bug 必须修掉**：上游对 `REG_EXPAND_SZ` 直接用 cmd `if exist` 判定，cmd 不展开该类型，所以含 `%VAR%` 的启动项一律被误判为「不存在」而漏报。本项目先展开再判，并保留原值到 `displayName` 便于用户辨认。

- [ ] **Step 6: 实现 `engine/src/services.cpp`**

  `EnumServicesStatusExW` 先以 0 缓冲区调用取得所需大小，再分配（两段式），遍历后对每个服务 `OpenSCManagerW` + `OpenServiceW` + `QueryServiceConfigW`——**`QueryServiceConfigW` 同样是两段式**，先取 size 再取 buffer。取到的 `lpBinaryPathName` 先经 `yh::strip_quotes_and_args`。

  判据：`yh::matches_interpreter(stripped, keywords)` → `service_interpreter`；否则 `!yh::path_in_prefixes(stripped, prefixes)` → `service_path_heuristic`。两者都命中时取 `service_interpreter`。

  **硬白名单先查**：`yh::is_hard_allowlisted(svcName, hard_allowlist)` 命中则**不产生任何发现**——`swprv` 与 `MicrosoftSoftware2ShadowCop4yProvider` 必须在这里被拦掉。

- [ ] **Step 7: 实现 `engine/src/self_check.cpp` 与 `engine/src/engine.cpp`**

  `yh_self_check` 填充 spec §3.1 的六个计数。`session0_visible` 的定义：枚举到且 `OpenProcess` 成功取得路径的 Session 0 进程数。非提权下应为 0，这是 Review Focus #1 在 UI 上唯一的暴露点。`elevated` 用 `GetTokenInformation(TokenElevation)`。

  `yh_engine_create` 调 `load_config`，失败返回 `nullptr`（不缓存半初始化状态）。`yh_finding_list_free` 与 `yh_string_free` 要能释放 `yh_engine_create` 及其所有 `yh_scan_*` 产出的内存，**不得有泄漏或二次释放**。

- [ ] **Step 8: 编译，确认通过**

  ```
  cmake --build engine/build --config Release
  ```
  Expected: 零错误零警告。

- [ ] **Step 9: 验证导出表——本任务唯一的「测试」，且不执行枚举**

  ```
  dumpbin /exports engine\build\Release\yinhuguard_engine.dll | findstr yh_
  ```
  Expected: 恰好列出八个 `yh_` 符号（`yh_engine_create`、`yh_engine_destroy`、`yh_self_check`、`yh_scan_processes`、`yh_scan_run_keys`、`yh_scan_services`、`yh_finding_list_free`、`yh_string_free`）。**这是刻意选择的无副作用验证手段**——用 `dumpbin` 而非运行 dll，因为 Global Constraints 禁止在本机执行枚举路径。

- [ ] **Step 10: 运行配置测试**

  ```
  engine\build\Release\test_config.exe
  ```
  Expected: 四个用例通过。**此程序不触碰真实系统。**

- [ ] **Step 11: Commit**

  ```bash
  git add engine/
  git commit -m "feat(engine): 三段真实系统枚举（编译+导出表验证，不在本机执行）"
  ```

---

### Task 4: Dart FFI 绑定层

**Files:**
- Create: `lib/src/ffi/bindings.dart`
- Create: `lib/src/ffi/engine_source.dart`
- Create: `lib/src/source/observation_source.dart`
- Create: `lib/src/source/engine_observation_source.dart`
- Create: `lib/src/source/fixture_observation_source.dart`
- Test: `test/bindings_layout_test.dart`

**Interfaces:**
- Consumes: Task 3 的导出符号与结构体布局；Task 2 的 `Observation`、`SelfCheck`
- Produces:
  ```dart
  // lib/src/source/observation_source.dart
  abstract interface class ObservationSource {
    Future<List<Observation>> scanProcesses();
    Future<List<Observation>> scanRunKeys();
    Future<List<Observation>> scanServices();
    Future<SelfCheck> selfCheck();
  }

  class EngineException implements Exception {
    final int code;      // 1 = 配置无效, 2 = 分配失败
    final String message;
  }

  // lib/src/ffi/engine_source.dart
  class EngineObservationSource implements ObservationSource {
    static Future<EngineObservationSource> open(String dllPath, String configPath);
    @override Future<List<Observation>> scanProcesses();
    @override Future<List<Observation>> scanRunKeys();
    @override Future<List<Observation>> scanServices();
    @override Future<SelfCheck> selfCheck();
    void close();
  }

  // lib/src/source/fixture_observation_source.dart
  class FixtureObservationSource implements ObservationSource {
    FixtureObservationSource.fromJson(Map<String, dynamic> json);
  }
  ```
  fixture JSON 结构：
  ```json
  {
    "self_check": {"elevated": false, "process_total": 690,
      "process_path_resolved": 434, "session0_visible": 0,
      "services_total": 360, "services_with_path": 358},
    "observations": [
      {"surface": "processes", "locator": "C:\\a\\hidden.exe",
       "display_name": "hidden.exe", "criteria": "file_attr_hs",
       "attributes_verified": true, "hidden": true, "system": false,
       "elevation_required": false, "covered": true, "timestamp": 1791945600.0}
    ]
  }
  ```

- [ ] **Step 1: 写失败测试 `test/bindings_layout_test.dart`**

  **本任务的核心测试是结构体布局断言，不是运行 dll。** 用 Dart `Struct` 的 `sizeOf` 与 `matchAsList` 把 spec §3.1 的布局钉死：

  ```dart
  // x64 布局：3 个 char* (24) + 5 个 int32 (20) = 44，
  // double 需 8 字节对齐 -> 补齐到 48，double 占 48..55 -> 合计 56
  test('YhFinding 布局与 spec §3.1 一致', () {
    expect(YhFinding.sizeOf(), 56);
  });

  test('YhSelfCheck 布局为 6 个 int32', () {
    expect(YhSelfCheck.sizeOf(), 6 * 4);
  });

  test('YhFindingList 布局为 指针 + size_t', () {
    expect(YhFindingList.sizeOf(), 8 * 2);
  });
  ```
  **spec §3.1 的 `YhFinding` 是 3 个指针（locator、display_name、criteria）+ 5 个 int32 + 1 个 double，不是 5 个指针** —— 早期版本有 `rule_id` 与 `evidence_url`，spec v2 收敛到原 bat 三段后已删除。若写这三个断言时数出的实测值与上式不符，**以 C++ 头文件为准并回头修 spec，不要改测试迁就实现**。结构体布局错位不会编译报错，只会在运行时读出垃圾，这是本项目最危险的静默失效点。

- [ ] **Step 2: 运行，确认失败**

  ```
  dart test test/bindings_layout_test.dart
  ```
  Expected: 失败，`YhFinding` 未定义。

- [ ] **Step 3: 创建 `lib/src/ffi/bindings.dart`**

  `final class YhFinding extends Struct` 字段顺序与 C++ 逐字一致；指针字段用 `Pointer<Utf8>`（因为 C++ 侧写的是 UTF-8），int32 用 `Int32`，double 用 `Double`。`YhFindingList` 用 `Pointer<Pointer<YhFinding>>` + `Size`。`typedef YhEngineCreateNative = Pointer<Void> Function(Pointer<Utf8>)` 等八个 typedef，`@Native` 标注 **`externalName`** 与 C++ 符号名一致。`@Native` 必须带 `symbol:` 指向真实 DLL 文件名，否则运行时找不到符号。

- [ ] **Step 4: 创建 `lib/src/source/observation_source.dart`**

  只放接口定义与 `EngineException`。**不要**在这里放任何实现。

- [ ] **Step 5: 实现 `EngineObservationSource`**

  `open` 用 `DynamicLibrary.open(dllPath)`，调 `yh_engine_create(configPath)`；返回 `nullptr` 时从 config 错误路径读出原因，抛 `EngineException(code: 1, ...)`。四个方法各自把 FFI 返回的 `YhFindingList` 转成 `List<Observation>`，转换完立即 `yh_finding_list_free`，逐串 `yh_string_free`。`close()` 调 `yh_engine_destroy` 并置空防二次释放。

  `scan*` 三方法标 `@Blocking` 之外，还要在 Dart 层用 `Isolate.run` 跑——枚举 360 个服务与数百个进程会阻塞 UI isolate，否则界面卡死。

- [ ] **Step 6: 实现 `FixtureObservationSource`**

  从 JSON 构造，**不引入 `dart:convert` 之外的依赖**。`scanProcesses()` 等按 `surface` 字段过滤后返回。缺失的 surface 返回空列表，**不抛异常**——fixture 只需要包含它想测的面。

  **命名映射逐字段照抄，不要靠约定推断**：fixture 与 JSON 报告一律 `snake_case`（`attributes_verified`、`elevation_required`、`self_check`、`session0_visible`），Dart 模型一律 `camelCase`（`attributesVerified`、`elevationRequired`、`SelfCheck.session0Visible`）。在 `FixtureObservationSource` 里写显式映射函数，**不要**依赖任何自动转换库。写一个断言：fixture 里含中文 locator 时，`scanProcesses()` 返回的 `Observation.locator` 与输入逐字节相同（Review Focus #3）。

- [ ] **Step 7: 运行测试，确认通过**

  ```
  dart test
  ```
  Expected: 全绿（布局断言 + Task 2 的既有测试）。

- [ ] **Step 8: Commit**

  ```bash
  git add lib/ test/
  git commit -m "feat(ffi): 绑定层、观测来源抽象与 fixture 来源"
  ```

---

### Task 5: 合成 fixture 数据与扫描编排

**Files:**
- Create: `fixtures/silverfox_sample.json`
- Create: `fixtures/clean_machine.json`
- Create: `lib/src/scan/orchestrator.dart`
- Test: `test/orchestrator_test.dart`

**Interfaces:**
- Consumes: Task 4 的 `ObservationSource`、Task 2 的 `Finding`、`SelfCheck`
- Produces:
  ```dart
  // lib/src/scan/orchestrator.dart
  class ScanResult {
    final SelfCheck selfCheck;
    final List<Finding> findings;
    final DateTime startedAt;
    final DateTime finishedAt;
  }

  class Orchestrator {
    Orchestrator(this.source);
    Future<void> scan(
      void Function(String surface, int index, int total) onProgress,
    );
    ScanResult get result;
    List<Finding> visibleFindings;      // !allowlisted
    List<Finding> allowlistedFindings;  // allowlisted
    int get uncoveredCount;             // covered == false 的条数 —— Review Focus #1
  }
  ```

- [ ] **Step 1: 写失败测试 `test/orchestrator_test.dart`**

  ```dart
  test('扫描编排按 processes -> run_keys -> services 顺序回调进度', () {
    // 断言 onProgress 的调用序列恰好是
    // ('processes',1,3) ('run_keys',2,3) ('services',3,3)
  });

  test('非提权 fixture 下 uncoveredCount 大于零且不被静默丢弃', () {
    final o = Orchestrator(FixtureObservationSource.fromJson(cleanMachineJson));
    await o.scan((_, __, ___) {});
    expect(o.uncoveredCount, greaterThan(0));
    expect(o.result.findings.any((f) => !f.covered), isTrue);
    // Review Focus #1：断言不存在「findings 为空却被当作干净」的路径
    expect(o.result.findings, isNotEmpty);
  });

  test('非提权时 selfCheck.session0Visible 为 0 且被如实报告', () {
    // Review Focus #1 的唯一暴露点
    final o = Orchestrator(FixtureObservationSource.fromJson(cleanMachineJson));
    await o.scan((_, __, ___) {});
    expect(o.result.selfCheck.elevated, isFalse);
    expect(o.result.selfCheck.session0Visible, 0);
    expect(o.result.selfCheck.processTotal, 690);
    expect(o.result.selfCheck.processPathResolved, 434);
  });

  test('三个 surface 的发现都被收集,含中文 locator', () {
    // fixture 里放 r'C:\Windows\Temp\临时 目录\文件.exe' 断言原样返回
  });

  test('单个 surface 抛异常时整体抛出,不返回半份结果', () {
    // 断言 EngineException 透传
  });
  ```

- [ ] **Step 2: 运行，确认失败**

  ```
  dart test test/orchestrator_test.dart
  ```
  Expected: 失败，`Orchestrator` 未定义。

- [ ] **Step 3: 创建两个 fixture**

  `fixtures/clean_machine.json`：模拟本机非提权实测基线（`process_total: 690`、`process_path_resolved: 434`、`session0_visible: 0`、`services_total: 360`、`services_with_path: 358`），且包含至少 3 条 `covered: false` 的进程观测与 1 条 `covered: false` 的服务观测。

  `fixtures/silverfox_sample.json`：包含每类 surface 的正例，至少各 1 条，其中必须包含：
  - 一条 `locator` 为中文与空格混合路径的观测（Review Focus #3）
  - 一条 `criteria: "file_attr_hs"` 且 `hidden: true` 的进程观测
  - 一条服务观测，其 `criteria` 为 `service_path_heuristic`、`locator` 形如 `C:\Users\Public\WindowsData\x.exe`
  - 一条**不应产生发现**的服务观测，`locator` 含 `svchost.exe -k swprv`（验证硬白名单，见 Task 6）

- [ ] **Step 4: 实现 `lib/src/scan/orchestrator.dart`**

  三个 `scan*` 顺序执行并回调进度。任一抛异常则整体重抛，**不返回部分结果**（`result` 保持未初始化）。`visibleFindings` / `allowlistedFindings` 按 `allowlisted` 切分，二者相加等于 `findings.length`——写一个断言固定这个不变式。

- [ ] **Step 5: 运行测试，确认通过**

  ```
  dart test
  ```
  Expected: 全绿。

- [ ] **Step 6: Commit**

  ```bash
  git add fixtures/ lib/src/scan/ test/
  git commit -m "feat(scan): 编排、进度回调与合成 fixture（含中文路径与未覆盖用例）"
  ```

---

### Task 6: 报告导出、日志与硬白名单落地

**Files:**
- Create: `lib/src/report/json_report.dart`
- Create: `lib/src/report/csv_report.dart`
- Create: `lib/src/report/log_writer.dart`
- Create: `rules/rules.json`
- Test: `test/report_test.dart`

**Interfaces:**
- Consumes: Task 5 的 `ScanResult`、Task 2 的 `redactPath`
- Produces:
  ```dart
  // lib/src/report/json_report.dart
  String toJsonReport(ScanResult r,
      {required String username, required String machineName});

  // lib/src/report/csv_report.dart
  /// 表头固定：surface,criteria,locator,display_name,hidden,system,
  ///           attributes_verified,covered,elevation_required,timestamp
  String toCsvReport(ScanResult r,
      {required String username, required String machineName});

  // lib/src/report/log_writer.dart
  Future<void> writeScanLog(ScanResult r, Directory outDir,
      {required String username, required String machineName});
  ```

- [ ] **Step 1: 写失败测试 `test/report_test.dart`**

  ```dart
  test('JSON 报告含 selfCheck 且 selfCheck.session0Visible 原样出现', () {
    // Review Focus #1：报告必须让「未覆盖」这件事可被远程读到
    final j = jsonDecode(toJsonReport(result, username: 'zhangwei', machineName: 'PC'));
    expect(j['self_check']['session0_visible'], 0);
    expect(j['self_check']['elevated'], false);
    expect(j['covered_count'], greaterThan(0));
  });

  test('JSON 与 CSV 都做用户名/机器名脱敏,路径其余保留', () {
    // fixture 用例含 r'C:\Users\zhangwei\AppData\Local\x.exe'
    // 期望 r'C:\Users\<USER>\AppData\Local\x.exe'
  });

  test('CSV 表头固定且列数一致', () {
    final csv = toCsvReport(result, username: 'u', machineName: 'm');
    expect(csv.split('\n').first,
      'surface,criteria,locator,display_name,hidden,system,'
      'attributes_verified,covered,elevation_required,timestamp');
    // 每行列数 == 10
  });

  test('CSV 正确转义 locator 里的逗号与引号', () {
    // 用含逗号的 display_name 固定 RFC4180 转义行为
  });

  test('covered=false 的条目在报告里可被筛出', () {
    expect(jsonDecode(toJsonReport(result, username: 'u', machineName: 'm'))
      ['findings'].where((f) => f['covered'] == false), isNotEmpty);
  });

  test('日志写入包含扫描时长与三个 surface 的条数', () {
    // 断言文件名形如 yinhuguard-2026-10-14T12-00-00.log
  });
  ```

- [ ] **Step 2: 运行，确认失败**

  ```
  dart test test/report_test.dart
  ```
  Expected: 失败，report 模块未定义。

- [ ] **Step 3: 创建 `rules/rules.json`**，内容逐字照抄 spec §8 的示例，含 `schema_version: 1`、`updated_at: "2026-10-14"`、六个解释器关键字、两个路径前缀、`hard_allowlist` 三项。

  **额外加一条断言型用例**：`test('rules.json 不含 vafdska 与 MiniFilterDrv 作为白名单或 IOC')` ——
  读文件断言 `hard_allowlist` 不含这两个名字，且整个文件文本不含它们。理由见 Global Constraints：它们查不到任何银狐出处，上游 `解禁杀毒软件.bat` 却把它们当驱动删除。

- [ ] **Step 4: 实现三个 report 模块**

  JSON 顶层键固定：`schema_version`、`started_at`、`finished_at`、`duration_ms`、`self_check`、`covered_count`、`findings[]`。每个 finding 的键固定：`surface`、`criteria`、`locator`、`display_name`、`hidden`、`system`、`attributes_verified`、`covered`、`elevation_required`、`allowlisted`、`timestamp`。

  **所有 locator 与 display_name 在序列化前统一过一次 `redactPath`。** 占位三字段 `confidence` / `suggestedAction` / `changeRecord` 一期恒为 `null`，**仍要在 JSON 里出现**，让二期报告格式不变。

  CSV 用 RFC 4180 转义：含 `,` `"` `\r` `\n` 的字段用双引号包裹，内部 `"` 翻倍。

  `writeScanLog` 在 `outDir` 写 `yinhuguard-<ISO 时间戳，冒号换成连字符>.log`，内容含自检结果、三 surface 条数、每条发现、每条 `covered=false` 的原因说明。

- [ ] **Step 5: 运行测试，确认通过**

  ```
  dart test
  ```
  Expected: 全绿。

- [ ] **Step 6: Commit**

  ```bash
  git add lib/src/report/ rules/ test/report_test.dart
  git commit -m "feat(report): JSON/CSV/日志导出与 rules.json（含 vafdska 反向断言）"
  ```

---

### Task 7: Flutter UI

**Files:**
- Create: `app/pubspec.yaml`
- Create: `app/lib/main.dart`
- Create: `app/lib/strings.dart`
- Create: `app/lib/ui/dashboard_page.dart`
- Create: `app/lib/ui/sidebar_tree.dart`
- Create: `app/lib/ui/findings_table.dart`
- Create: `app/lib/ui/selfcheck_panel.dart`
- Create: `app/lib/ui/export_bar.dart`
- Modify: `pubspec.yaml`（把 `lib/` 暴露为可被 app 依赖的包）

**Interfaces:**
- Consumes: Task 5 的 `Orchestrator`/`ScanResult`、Task 6 的三个 report 函数、Task 2 的 `Finding`
- Produces: 无下游任务依赖，仅供 Task 8/9 使用

- [ ] **Step 1: 装 Flutter SDK 到 `<flutter-sdk>`**

  从 flutter.dev 下载 Windows stable，解压到 `<flutter-sdk>`，把 `<flutter-sdk>\bin` 加到 PATH 并验证：

  ```
  flutter --version
  flutter doctor
  ```
  Expected: 版本号正常输出；`flutter doctor` 对 **Visual Studio Community 2026** 报绿色（VS 已确认存在）。若 `Android toolchain` 报错可忽略——本项目只做 Windows desktop。

- [ ] **Step 2: 调整项目布局**

  `pubspec.yaml` 改名 `name: yinhuguard_core`，`lib/` 为纯 Dart 包。`app/` 是 Flutter 包，`pubspec.yaml` 用 `dependencies: yinhuguard_core: path: ../`。

- [ ] **Step 3: 创建 `app/lib/strings.dart`**

  一个 `final Map<String, String> kStrings`，键如 `appTitle` / `scanProgress` / `selfCheckTitle` / `uncoveredNotice` / `exportJson` / `exportCsv` / `surfaceProcesses` / `surfaceRunKeys` / `surfaceServices`。值全为简体中文。**不要**用 `gen-l10n`，spec §7 要求手写字典。

- [ ] **Step 4: 创建 `app/lib/main.dart`**

  `runApp(YinHuGuardApp())`。构造时注入 `ObservationSource`——生产注入 `EngineObservationSource`，**测试与开发态注入 `FixtureObservationSource`（读 `fixtures/clean_machine.json`）**。加一个 `--fixture <path>` 启动参数走 fixture 源。

  **默认不得**在开发机上自动启动真实扫描。启动后界面就绪但扫描按钮待用户点击（对照 Global Constraints：禁止在本机执行枚举路径）。

- [ ] **Step 5: 创建侧边栏与表格**

  `SidebarTree`：固定三项，对应 spec §4.1–4.3 的三个 surface，显示每项条数。
  `FindingsTable`：`DataTable`，默认按 surface 分组、组内 timestamp 倒序（spec §7）。列 = locator / criteria / hidden / system / covered / elevation_required。**白名单条目折叠到单独分组**，标题写明「已按白名单折叠 N 条」。`allowlisted` 的行用灰色，不隐藏。

- [ ] **Step 6: 创建自检面板与「未覆盖」提示**

  `SelfCheckPanel`：显示 `elevated`、`processTotal`、`processPathResolved`、`session0Visible`、`servicesTotal`、`servicesWithPath` 六项。**`session0Visible == 0 && elevated == false` 时必须显示醒目提示**，文案明确写出「Session 0 进程路径未读取，本结论不覆盖系统进程」，**不得显示「未发现问题」**。这是 Review Focus #1 在 UI 上唯一的兑现点，也是整个应用最重要的一行字。

- [ ] **Step 7: 创建导出栏**

  两个按钮调 Task 6 的 `toJsonReport` / `toCsvReport`，保存对话框默认文件名 `yinhuguard-report-<日期>.json` / `.csv`。每次扫描结束自动调 `writeScanLog`。

- [ ] **Step 8: 编译 Windows 桌面产物**

  ```
  cd app
  flutter build windows --release
  ```
  Expected: 生成 `app/build/windows/x64/runner/Release/yinhuguard.exe`。**构建过程不执行任何扫描。**

- [ ] **Step 9: 用 fixture 模式验证界面（唯一允许的「跑一次」）**

  ```
  cd app
  flutter run -d windows -- --fixture ..\fixtures\clean_machine.json
  ```
  Expected: 界面显示三个 surface 的条数、`covered=false` 的条目数与自检面板的「Session 0 未读取」提示。**确认不出现「未发现问题」。**
  验证完关闭，**不得**再以真实扫描方式启动。

- [ ] **Step 10: Commit**

  ```bash
  git add app/ pubspec.yaml
  git commit -m "feat(ui): Flutter 仪表盘、侧边栏、自检面板与导出栏"
  ```

---

### Task 8: CLI 模式

**Files:**
- Create: `app/lib/cli.dart`
- Modify: `app/lib/main.dart`
- Test: `test/cli_args_test.dart`

**Interfaces:**
- Consumes: Task 7 的 `--fixture` 参数模式、Task 5 的 `Orchestrator`、Task 6 的 report 函数
- Produces:
  ```dart
  // app/lib/cli.dart
  sealed class CliAction {}
  class RunScan extends CliAction { final String? jsonOutPath; }
  class InvalidArgs extends CliAction { final String message; }

  CliAction parseArgs(List<String> args);
  // 无参 -> RunScan(jsonOutPath: null)
  // --scan -> RunScan(jsonOutPath: null)
  // --json <path> -> RunScan(jsonOutPath: <path>)
  // 其它 -> InvalidArgs
  ```

- [ ] **Step 1: 写失败测试 `test/cli_args_test.dart`**

  纯 Dart 测试，不启动 UI，不连引擎：
  ```dart
  test('--json 必须带路径', () {
    expect(parseArgs(['--json']), isA<InvalidArgs>());
    expect(parseArgs(['--json', 'out.json']), isA<RunScan>()
      .having((a) => a.jsonOutPath, 'jsonOutPath', 'out.json'));
  });
  test('未知参数 -> InvalidArgs 且 message 含该参数', () {
    expect(parseArgs(['--scan-all']), isA<InvalidArgs>()
      .having((a) => a.message, 'message', contains('--scan-all')));
  });
  test('无参等价 --scan', () {
    expect(parseArgs([]), isA<RunScan>().having((a) => a.jsonOutPath, 'p', isNull));
  });
  ```

- [ ] **Step 2: 运行，确认失败**

  ```
  dart test test/cli_args_test.dart
  ```
  Expected: 失败，`parseArgs` 未定义。

- [ ] **Step 3: 实现 `app/lib/cli.dart`**

  照 Interfaces 块。**不要**在 `parseArgs` 里做任何 IO。

- [ ] **Step 4: 接进 `main.dart`**

  `main()` 先解析参数：命中 `InvalidArgs` 则打印 message 到 stderr 并 `exitCode = 2`；命中 `RunScan` 且非 GUI 模式则跑 `Orchestrator` + 可选写 JSON + 打印条数摘要后退出。命中 `--fixture` 的一律注入 `FixtureObservationSource`。

  **stdio 模式（`--scan` / `--json`）在本机不得执行真实扫描**——开发验证只用 `--scan --fixture ..\fixtures\clean_machine.json` 组合。

- [ ] **Step 5: 运行测试与 fixture 验证**

  ```
  dart test
  cd app && flutter build windows --release
  app\build\windows\x64\runner\Release\yinhuguard.exe --scan --fixture ..\fixtures\clean_machine.json
  ```
  Expected: 打印三个 surface 的条数与 `未覆盖 N 条`。**不启动 GUI，不连真实引擎。**

- [ ] **Step 6: Commit**

  ```bash
  git add app/lib test/
  git commit -m "feat(cli): --scan / --json 参数解析与 stdio 输出"
  ```

---

### Task 9: 提权重扫描入口

**Files:**
- Create: `app/lib/elevate.dart`
- Modify: `app/lib/main.dart`
- Modify: `app/lib/ui/selfcheck_panel.dart`
- Test: `test/elevate_args_test.dart`

**Interfaces:**
- Consumes: Task 7 的 `SelfCheckPanel` 与 `--fixture` 参数模式、Task 4 的 `EngineObservationSource.open`
- Produces:
  ```dart
  // app/lib/elevate.dart
  bool get isElevated;                        // GetTokenInformation(TokenElevation) 的 Dart 侧探测
  String buildRelaunchArgs(List<String> argv); // 保留 --fixture，其余原样透传
  ```

- [ ] **Step 1: 写失败测试 `test/elevate_args_test.dart`**

  ```dart
  test('重扫描时保留 --fixture 参数', () {
    expect(buildRelaunchArgs(['--scan', '--fixture', '..\\fixtures\\clean_machine.json']),
      contains('--fixture'));
  });
  test('不带 --fixture 时不凭空造出路径', () {
    expect(buildRelaunchArgs(['--scan']), isNot(contains('--fixture')));
  });
  test('不重复累积 relaunch 标记', () {
    final a = buildRelaunchArgs(['--scan']);
    expect(buildRelaunchArgs(a), isNot(contains('--relaunched')));
  });
  ```
  本测试只验参数拼装，**不调用 ShellExecuteEx**，因此不触碰开发机。

- [ ] **Step 2: 运行，确认失败**

  ```
  dart test test/elevate_args_test.dart
  ```
  Expected: 失败，`buildRelaunchArgs` 未定义。

- [ ] **Step 3: 实现 `app/lib/elevate.dart`**

  `isElevated` 用 `dart:ffi` 直调 `GetTokenInformation` + `TokenElevation`，**不 import `package:win32`**，保持依赖为零。`buildRelaunchArgs` 纯字符串操作：保留 `--fixture <path>` 对与其后的路径，其余原样透传；若入参已含 `--relaunched` 则不再追加。

- [ ] **Step 4: 在 `main.dart` 接入提权重启**

  `SelfCheckPanel` 的 `elevated == false` 时显示「以管理员身份重新扫描」按钮。点击时：取当前 exe 完整路径 → `buildRelaunchArgs` 拼参数 → 用 `ShellExecuteExW` 配 `lpVerb = "runas"` 启动自身 → 等新实例起来后当前实例自行退出。**新实例必须带 `--relaunched` 标记，避免无限弹 UAC 循环**——若该标记已存在而 `elevated` 仍为 false，说明提权被用户取消，此时按钮改为禁用并提示原因。

  用户取消 UAC 是正常路径，不是错误。取消时**不得**把扫描结果呈现为「未发现问题」。

- [ ] **Step 5: 在 `SelfcheckPanel` 显示提权状态**

  `elevated == false` 时，`session0Visible == 0` 旁边必须并列显示「未提权，Session 0 未覆盖」。这条与 Task 7 Step 6 的提示是同一条 Review Focus #1 文案，此处只补提权状态维度。

- [ ] **Step 6: 运行测试与编译**

  ```
  dart test
  cd app && flutter build windows --release
  ```
  Expected: 全绿，exe 重新产出。**不点击提权按钮，不在本机触发 UAC。**

- [ ] **Step 7: Commit**

  ```bash
  git add app/lib test/
  git commit -m "feat(ui): 提权重扫描入口与防循环标记"
  ```

---

### Task 10: 打包与首次运行说明

**Files:**
- Create: `package/build_package.ps1`
- Create: `package/首次运行说明.md`
- Create: `CHANGELOG.md`

**Interfaces:**
- Consumes: Task 7 的构建产物、Task 6 的 `rules/rules.json`
- Produces: `dist/yinhuguard-<日期>.zip`，内含 `yinhuguard.exe`、`rules.json`、`flutter_windows.dll`、`data/`、说明文档

- [ ] **Step 1: 写 `package/build_package.ps1`**

  纯 ASCII（除引用的中文文件名外不做字符串拼接）。步骤：清理 `dist/` → `flutter build windows --release` → 拷贝 `app/build/windows/x64/runner/Release/` 全部内容到 `dist/yinhuguard/` → 拷贝 `rules/rules.json` 到该目录 → 压缩为 `dist/yinhuguard-<yyyyMMdd>.zip`。

  **沿用既有教训：脚本内不放中文字面量。** 书名/文件名一律从 ASCII 路径读入，脚本自身除 BOM 外纯 ASCII，否则中文文件名在 PowerShell 下会被读成乱码。压缩包内目录名用 ASCII `yinhuguard/`，中文说明文档用 `README-zh.txt` 这个 ASCII 文件名承载中文内容。

- [ ] **Step 2: 写 `package/首次运行说明.md` 并另存为 `README-zh.txt`**

  内容必须含：如何解压、如何运行、**SmartScreen 蓝色窗口的处理步骤**（点「更多信息」→「仍要运行」）、以及一段「本工具只读、不修改系统」的明确声明与「仅供排查，不作为唯一判据」的免责说明。中文正文写在 `.md` 里，打包时复制为 ASCII 文件名。

- [ ] **Step 3: 写 `CHANGELOG.md`**

  一期条目：只读三段扫描、覆盖 spec §4.1–4.3、修正上游 WMI Session 0 漏检与 `2^>nul` 静默丢弃。

- [ ] **Step 4: 运行打包脚本，确认产物完整**

  ```
  powershell -File package\build_package.ps1
  ```
  Expected: 生成 `dist/yinhuguard-<日期>.zip`；用 `tar -tf` 或 `Expand-Archive` 到临时目录列出内容，确认**五个必需项齐全**：`yinhuguard.exe`、`rules.json`、`flutter_windows.dll`、`data/`、`README-zh.txt`。

- [ ] **Step 5: Commit**

  ```bash
  git add package/ CHANGELOG.md
  git commit -m "build: 便携 zip 打包脚本与首次运行说明"
  ```

---

## 交付后交给用户的事

计划到此结束。**交付时必须一并说明以下三点，不得省略：**

1. **本机未执行过任何枚举路径。** 编译、导出表检查、纯函数单测、fixture 跑通都做了；真实 Win32 枚举一次没跑。
2. **首次运行最可能失败在 `NtQueryInformationProcess` / `QueryFullProcessImageNameW` 的 FFI 声明与结构体布局，以及 `QueryServiceConfigW` 的两段式调用。** 这些编译期不报错、运行时静默返回空（spec §11.3）。首屏的自检面板就是为暴露它们而做的：若 `session0_visible` 为 0 且 `elevated` 为 false，而 `process_path_resolved` 异常高或为 0，即说明枚举路径有问题。
3. **`--scan` 在真实模式下会枚举本机全部进程与服务。** 首次真实运行建议先在虚拟机里做。