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

const String kSurfaceProcesses = '隐藏进程';
const String kSurfaceRunKeys = '隐藏启动项';
const String kSurfaceServices = '可疑服务';

/// 与 spec §4.1–4.3 的三段一一对应，展示在上游那套「1/3、2/3、3/3」的位置上。
const String kSurfaceProcessesSub = '对应上游 扫描1/3';
const String kSurfaceRunKeysSub = '对应上游 扫描2/3';
const String kSurfaceServicesSub = '对应上游 扫描3/3';

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
const String kSession0WarningTitle = '系统进程未被覆盖，本结论不完整';
const String kSession0WarningBody =
    '当前不是管理员权限，Session 0 的进程路径读不到，这部分没有被检查过。\n'
    '「没有发现问题」在这里只意味着「这一部分没看」，不等于机器干净。\n'
    '如需完整结论，请以管理员身份重新扫描。';

const String kElevateButton = '以管理员身份重新扫描';
const String kElevateCancelled = '提权被取消，仍以普通权限运行。系统进程依然未被覆盖。';
const String kElevateFailed = '提权失败：';
const String kElevatedAlready = '已以管理员身份运行，覆盖范围完整。';

// ---- 结果列表 ----

const String kFindingsTitle = '发现';
const String kEmptyForSurface = '这个扫描面没有命中。';
const String kNoScanYet = '尚未扫描。点击「开始扫描」运行三段检测。';

/// 空结果旁的提示。任何「没有命中」的表述都必须带上这句，
/// 否则读者会把它当成「没有问题」。
const String kEmptyCaveat =
    '注意：没有命中不代表机器干净。请对照上方「本次扫描的覆盖范围」确认哪些部分没被检查。';

const String kUncoveredBadge = '未覆盖';
const String kAllowlistedBadge = '已按白名单折叠';
const String kHiddenBadge = '隐藏属性';
const String kSystemBadge = '系统属性';
const String kNeedsElevationBadge = '需要提权';

const String kColumnLocator = '位置';
const String kColumnDisplayName = '具体对象';
const String kColumnCriteria = '判据';
const String kColumnFlags = '标记';

/// 判据的可读名。给用户看的，不是给程序看的，所以不复用 kCriteria 的标识符。
const Map<String, String> kCriteriaLabels = <String, String>{
  'file_attr_hs': '文件带隐藏/系统属性',
  'service_interpreter': '服务路径含解释器调用',
  'service_path_heuristic': '服务路径不在系统目录',
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
