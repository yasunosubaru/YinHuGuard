// lib/src/model/self_check.dart
//
// 自检结果。存在的理由：把「哪些东西没看到」变成界面上能读懂的一行字。
//
// **这个模型存在的全部意义是避免一个永远关不掉的警告。**
// 最初只有一个 `sessionZeroVisible == 0` 的判断，结果是：即使提权成功，扫描
// 那一刻总有进程退出、总有保护进程不放行，于是面板永远红着。用两周之后
// 用户就会开始无视红色警告——那正是这个工具从头到尾在防的事。
//
// 所以「没查到」必须分两类：
//   permission —— 提权能解决   → 红色，可行动，告诉用户去点「完整扫描」
//   residual   —— 提权也解决不了（枚举瞬间退出 / 保护进程）→ 灰色，一句话带过
//
// 有了这个分层，「覆盖完整」才是一个能达到的状态，警告才有意义。

class SelfCheck {
  final bool elevated;
  final int processTotal;
  final int processPathResolved;

  /// Session 0 中**成功取到路径**的进程数。非提权时应为 0。
  final int session0Visible;

  final int servicesTotal;
  final int servicesWithPath;

  /// 取不到路径、且原因是 OpenProcess 被 ACCESS_DENIED 拒的进程数。提权能解决。
  final int processUnresolvedPermission;

  /// 取不到路径、但不是权限问题的进程数（枚举瞬间退出、保护进程等）。
  final int processUnresolvedOther;

  final int servicesUnresolvedPermission;
  final int servicesUnresolvedOther;

  SelfCheck({
    required this.elevated,
    required this.processTotal,
    required this.processPathResolved,
    required this.session0Visible,
    required this.servicesTotal,
    required this.servicesWithPath,
    this.processUnresolvedPermission = 0,
    this.processUnresolvedOther = 0,
    this.servicesUnresolvedPermission = 0,
    this.servicesUnresolvedOther = 0,
  });

  /// 提权能解决的缺口总数。>0 就该显示红色警告。
  int get permissionGaps =>
      processUnresolvedPermission + servicesUnresolvedPermission;

  /// 提权也解决不了的残留总数。>0 只该灰字提一句。
  int get residualGaps => processUnresolvedOther + servicesUnresolvedOther;

  /// 权限层面还有没看到的。
  ///
  /// `!elevated` 是一道保险：非提权时 Session 0 必然有一整块看不到，
  /// 不该依赖引擎是否恰好把 ACCESS_DENIED 逐条算清楚。
  bool get hasPermissionGap => !elevated || permissionGaps > 0;

  bool get hasResidual => residualGaps > 0;

  /// 覆盖完整。
  ///
  /// 条件必须全部成立：已提权、两个面都真的枚举到了东西、权限层面零缺口。
  /// 加 `> 0` 的计数检查是为了挡住「枚举整个失败但返回了 0 个」——
  /// 那种情况下只看 permissionGaps 会算成 0，从而冒充完整。
  ///
  /// 注意**不**把 residualGaps 算进来：进程在扫描瞬间退出是竞态，不是缺陷。
  /// 把它算进来，这个状态就永远达不到，警告也就回到「永不熄灭」的老问题。
  bool get coverageComplete =>
      elevated &&
      processTotal > 0 &&
      servicesTotal > 0 &&
      permissionGaps == 0;

  factory SelfCheck.fromJson(Map<String, dynamic> json) {
    int intOr(String key) => (json[key] as num?)?.toInt() ?? 0;
    return SelfCheck(
      elevated: json['elevated'] as bool,
      processTotal: intOr('process_total'),
      processPathResolved: intOr('process_path_resolved'),
      session0Visible: intOr('session0_visible'),
      servicesTotal: intOr('services_total'),
      servicesWithPath: intOr('services_with_path'),
      processUnresolvedPermission: intOr('process_unresolved_permission'),
      processUnresolvedOther: intOr('process_unresolved_other'),
      servicesUnresolvedPermission: intOr('services_unresolved_permission'),
      servicesUnresolvedOther: intOr('services_unresolved_other'),
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'elevated': elevated,
        'process_total': processTotal,
        'process_path_resolved': processPathResolved,
        'session0_visible': session0Visible,
        'services_total': servicesTotal,
        'services_with_path': servicesWithPath,
        'process_unresolved_permission': processUnresolvedPermission,
        'process_unresolved_other': processUnresolvedOther,
        'services_unresolved_permission': servicesUnresolvedPermission,
        'services_unresolved_other': servicesUnresolvedOther,
      };
}