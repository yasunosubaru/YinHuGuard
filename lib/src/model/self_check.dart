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

  /// 未解析条目总数。引擎把 ACCESS_DENIED 与「其它」分开记，但这里要的是总数。
  int get unresolved =>
      processUnresolvedPermission + servicesUnresolvedPermission +
      processUnresolvedOther + servicesUnresolvedOther;

  /// 提权能解决的缺口总数。>0 就该显示红色警告。
  ///
  /// **按提权状态分类，不按引擎的子分类。** 未提权时 Session 0 一整块必然读不到，
  /// 那是权限问题、提权能解决——所以**所有**未解析条目都算权限缺口。
  /// 已提权时还读不到的是保护进程（MsMpEng 之类），提权也解决不了——
  /// 所以**所有**未解析条目都算残留。
  ///
  /// 不采用引擎给出的 `*_permission` / `*_other` 子分类来定这个结论：
  /// 那份分类在非提权时并不可靠（进程瞬间退出与 ACCESS_DENIED 很难区分），
  /// 而把分类权交给它，等于允许引擎的误分类把红色警告整个关掉。
  int get permissionGaps => !elevated ? unresolved : 0;

  /// 提权也解决不了的残留总数。>0 只该灰字提一句。
  int get residualGaps => elevated ? unresolved : 0;

  /// 权限层面还有未看到的。
  bool get hasPermissionGap => permissionGaps > 0;

  bool get hasResidual => residualGaps > 0;

  /// 覆盖完整。
  ///
  /// 条件必须全部成立：已提权、两个面都真的枚举到了东西、权限层面零缺口、
  /// **且没有任何残留未覆盖项**（残留属于竞态/保护进程，虽属正常但仍属未覆盖）。
  /// 加 `> 0` 的计数检查是为了挡住「枚举整个失败但返回了 0 个」——
  /// 那种情况下只看 permissionGaps 会算成 0，从而冒充完整。
  bool get coverageComplete =>
      elevated &&
      processTotal > 0 &&
      servicesTotal > 0 &&
      permissionGaps == 0 &&
      residualGaps == 0;

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