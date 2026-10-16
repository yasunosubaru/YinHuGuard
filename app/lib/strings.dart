// app/lib/strings.dart
//
// 界面上所有会被人读到的字。集中放一处，二期补英文时只改这一个文件。
//
// 故意不用 gen-l10n：一期只有一种语言，ARB + 代码生成的样板量远大于收益，
// 而它的校验对「文案还没想好」的阶段反而是负担。手写字典同样为零成本，
// 二期接 gen-l10n 也只差把这个文件换掉。

const String kAppTitle = '银狐木马排查工具';

/// 副标题里写明「只读」，因为这是用户决定敢不敢双击它的首要依据。
const String kAppSubtitle = '只读排查 · 不修改系统 · 不上传任何数据';

// ---- 扫描控制 ----

/// 启动后停在按钮上而不是自动开扫：一个安全工具第一次运行时
/// 未经请求就枚举全机进程，是最容易被当成恶意软件的行为。
const String kStartScan = '开始扫描';
const String kRescan = '重新扫描';
const String kScanning = '正在扫描…';

/// 进度条旁的说明。顺序必须与 `kScanOrder` 一致，否则进度条走到第三个面
/// 用户还在等「服务」之后的进度。
const String kScanProgressHint =
    '七个面依次执行，耗时递增：进程 → 启动项 → 服务 → 注册表载荷 → '
    '驱动服务 → 文件落点 → 计划任务';

/// 侧边栏的「不过滤」入口。
const String kSurfaceAll = '全部';

const String kSurfaceProcesses = '隐藏进程';
const String kSurfaceRunKeys = '隐藏启动项';
const String kSurfaceServices = '可疑服务';

/// 与 spec §4.1–4.3 的三段一一对应，展示在上游那套「1/3、2/3、3/3」的位置上。
const String kSurfaceProcessesSub = '对应上游 扫描1/3';
const String kSurfaceRunKeysSub = '对应上游 扫描2/3';
const String kSurfaceServicesSub = '对应上游 扫描3/3';

// ---- 二期深度扫描的面 ----

const String kSurfaceRegistryPayloads = '注册表载荷';
const String kSurfaceRegistryPayloadsSub = '不是启动项，只删启动项会复发';

const String kSurfaceDrivers = '驱动服务';
const String kSurfaceDriversSub = 'BYOVD 全有合法签名，按已知名单认';

const String kSurfaceFileDrops = '文件落点';
const String kSurfaceFileDropsSub = '已知路径与已知文件名';

const String kSurfaceScheduledTasks = '计划任务';
const String kSurfaceScheduledTasksSub = '走 Task Scheduler COM，耗时最长';

// ---- 自检面板 ----

const String kSelfCheckTitle = '本次扫描的覆盖范围';
const String kElevated = '管理员权限';
const String kYes = '是';
const String kNo = '否';
const String kProcessTotal = '进程总数';
const String kProcessPathResolved = '取到路径的进程';
const String kSession0Visible = 'Session 0 可见进程';
const String kServicesTotal = '服务总数';
const String kServicesWithPath = '取到 ImagePath 的服务';

/// 全应用最重要的一句话。未提权时 Session 0 的进程路径一条都拿不到，
/// 而「什么都没查到」会被读成「机器是干净的」——这个误读必须被界面挡住。
const String kCoverageIncompleteTitle = '本次扫描的覆盖范围不完整';

/// 未提权的具体说法。
const String kSession0WarningBody =
    '当前不是管理员权限，Session 0 的进程路径读不到，这部分没有被检查过。\n'
    '「没有发现问题」在这里只意味着「这一部分没看」，不等于机器干净。\n'
    '如需完整结论，请以管理员身份重新扫描。';

/// 引擎层失败：两个主面一个都没枚举到。这次结果整个不可用。
/// （界面必须显式报这一档 —— 否则空发现列表会被读成「机器干净」。）
const String kSelfCheckFailedTitle = '自检异常：什么都没枚举到';

const String kSelfCheckFailedBody =
    '这次扫描没有枚举到任何进程或服务，说明引擎没有正常工作。\n'
    '本次结果不可用，请重新扫描；若反复出现，请重新解压一份完整的包再试。';

/// 兼容旧名，界面标题统一走 kCoverageIncompleteTitle。
const String kSession0WarningTitle = kCoverageIncompleteTitle;

const String kElevateButton = '完整扫描（提权重跑）';
const String kElevateHint =
    '完整扫描 = 以管理员身份重新跑一遍。Session 0 的进程只有管理员权限才读得到，'
    '不提升的话那一整块永远看不到。';
const String kElevateCancelled = '提权被取消，仍以普通权限运行。系统进程依然未被覆盖。';
const String kElevateFailed = '提权失败：';
const String kElevatedAlready = '已以管理员身份运行。';

/// 覆盖完整 —— 判定最严的一档：连残留都没有。真机上罕见（保护进程永远读不到），
/// 但只要差一点就用下面那档「能检查的都已检查」，绝不放宽这一句的字面含义。
const String kCoverageCompleteTitle = '覆盖完整';

/// 说清楚「完整」的边界，否则用户会把这句话读成「保证没病毒」。
const String kCoverageCompleteBody =
    '本次所有进程与服务都已检查，没有因权限而遗漏的部分。\n'
    '这不代表机器一定干净——判定用的是启发式规则，仍需人确认。';

/// 已提权、权限零缺口、但仍有读不到的条目 —— 真机上这就是常态结论。
///
/// 措辞里**不能出现「完整」**：列表里还有带「未覆盖」标记的条目，
/// 「蓝色覆盖完整 + 红色未覆盖同屏」正是用户实测报过的自相矛盾。
const String kCoverageReachedTitle = '已提权：能检查的都已检查';

/// 读不到的条目会逐条以「未覆盖」标在列表里。用发现级的 uncoveredCount
/// 来分流，不能只看 SelfCheck 的聚合数字 —— 驱动、注册表这些面没有自检计数。
const String kCoverageReachedBodyWithList =
    '管理员权限下，权限层面没有缺口。仍有少数条目读不到证据（系统保护进程、'
    '扫描瞬间退出或数据不可读）—— 已在下方逐条标为「未覆盖」，属正常现象，不影响结论。';

/// 读不到的条目没有进入发现列表时的说法（例如进程在枚举瞬间退出、没留下条目）。
const String kCoverageReachedBodyResidualOnly =
    '管理员权限下，权限层面没有缺口。另有 %d 个进程/服务在扫描瞬间已退出或受系统保护，'
    '读不到路径 —— 属正常现象，不影响结论。';

// ---- 结果列表 ----

const String kFindingsTitle = '发现';
const String kEmptyForSurface = '这个扫描面没有命中。';
const String kNoScanYet = '尚未扫描。点击「开始扫描」运行全部七个扫描面。';

/// 空结果旁的提示。任何「没有命中」的表述都必须带上这句，
/// 否则读者会把它当成「没有问题」。
const String kEmptyCaveat =
    '注意：没有命中不代表机器干净。请对照上方「本次扫描的覆盖范围」确认哪些部分没被检查。';

const String kUncoveredBadge = '未覆盖';
const String kAllowlistedBadge = '已按白名单折叠';
const String kHiddenBadge = '隐藏属性';
const String kSystemBadge = '系统属性';
const String kNeedsElevationBadge = '需要提权';

/// 已提权时的正确叫法：管理员下还会 ACCESS_DENIED 的只能是系统保护（PPL 等），
/// 再说「需要提权」就是错的。
const String kProtectedBadge = '系统保护';

/// 未覆盖条目的行内原因，按提权状态分支。已提权时不可能再是权限问题：
/// 让用户「以管理员身份重跑」而他已经这样做了，只会毁掉整份报告的信任。
const String kUncoveredNeedsElevation = '权限不足，未检查。以管理员身份重跑才能覆盖。';
const String kUncoveredDataUnreadable = '无法判断（环境变量无法展开或数据不可读）。';

/// 已提权才可能出现：PPL 保护进程（csrss.exe 这类），任何权限都读不到。
const String kUncoveredProtected =
    '受系统保护，管理员权限也读不到（属正常残留）。若该对象不是已知的 Windows 系统进程，请人工核实。';

/// 已提权、非权限类：对象没有映像文件（伪进程）或数据确实读不出。
const String kUncoveredNoEvidence = '无法读取该条目的证据（对象没有映像文件或数据不可读）。';

const String kColumnLocator = '位置';
const String kColumnDisplayName = '具体对象';
const String kColumnCriteria = '判据';
const String kColumnFlags = '标记';

/// 判据的可读名。给用户看的，不是给程序看的，所以不复用 kCriteria 的标识符。
const Map<String, String> kCriteriaLabels = <String, String>{
  'file_attr_hs': '文件带隐藏/系统属性',
  'service_interpreter': '服务路径含解释器调用',
  'service_path_heuristic': '服务路径不在系统目录',
  // ---- 二期 ----
  'name_match': '命中已知威胁名单',
  'path_heuristic': '位置不在预期目录',
};

// ---- 导出与日志 ----

const String kExportJson = '导出 JSON';
const String kExportCsv = '导出 CSV';
const String kExportedTo = '已导出到：';
const String kLogWritten = '扫描日志：';

// ---- 错误 ----

const String kEngineError = '引擎错误';
const String kConfigError = '配置文件无效，程序拒绝启动';
const String kConfigErrorHint = '配置文件是纯数据，出问题时会指出具体是哪个键。修好后再启动。';

// ---- 首次运行说明 ----

const String kSmartScreenHint =
    '若首次运行被 Windows 拦截，点「更多信息」→「仍要运行」。本工具未做代码签名。';
