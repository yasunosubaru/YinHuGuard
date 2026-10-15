// lib/src/model/self_check.dart
//
// 自检结果。存在的唯一理由是：把「哪些东西没看到」变成界面上的一行字。
//
// 最重要的一个字段是 [session0Visible]。实测本机非提权状态下，Session 0 的
// 220 个进程路径**一个都拿不到**；如果这个数字是 0、而 elevated 也是 false，
// 界面就必须明说「系统进程未覆盖」，绝不能让用户把「什么都没查到」读成
// 「机器是干净的」。这是本项目最危险的一处误读。

class SelfCheck {
  final bool elevated;
  final int processTotal;
  final int processPathResolved;

  /// Session 0 中**成功取到路径**的进程数。非提权时应为 0。
  final int session0Visible;

  final int servicesTotal;
  final int servicesWithPath;

  SelfCheck({
    required this.elevated,
    required this.processTotal,
    required this.processPathResolved,
    required this.session0Visible,
    required this.servicesTotal,
    required this.servicesWithPath,
  });

  /// 有进程拿到了 PID 却拿不到路径 —— 这些就是「本来该看、没看到」的。
  bool get hasUnresolvedProcesses => processPathResolved < processTotal;

  /// 有服务枚举到了却拿不到 ImagePath。
  bool get hasUnresolvedServices => servicesWithPath < servicesTotal;

  /// 结论是否**不完整**。
  ///
  /// 刻意不做成「session0Visible == 0」那种全有全无的判断。历史上它就是这么写的，
  /// 后果是：非提权时只要有一条 Session 0 路径侥幸解析成功（220 条里成功 1 条），
  /// 红色警告整块消失，界面反而给出一个比真实覆盖更乐观的印象。
  /// 现在的规则是**有任何一条该看而没看的证据，就算不完整**。
  ///
  /// 非提权本身直接判不完整：Session 0 是权限拦住的，没提权就必然有一整块没看，
  /// 不需要等计数来证明。
  bool coverageIncomplete(int uncoveredCount) =>
      !elevated || hasUnresolvedProcesses || hasUnresolvedServices || uncoveredCount > 0;

  /// 能否说「覆盖完整」。这个说法很强，所以条件必须全部成立：
  /// 已提权、两个面都枚举到了东西、且没有一条没解析出来。
  ///
  /// 加 `> 0` 的计数检查是为了挡住「枚举整个失败但返回了 0 个」这种情形 ——
  /// 那种情况下上一条会算「没有未解析项」，从而冒充完整。
  bool get coverageComplete =>
      elevated &&
      processTotal > 0 &&
      servicesTotal > 0 &&
      processPathResolved == processTotal &&
      servicesWithPath == servicesTotal;

  factory SelfCheck.fromJson(Map<String, dynamic> json) {
    return SelfCheck(
      elevated: json['elevated'] as bool,
      processTotal: json['process_total'] as int,
      processPathResolved: json['process_path_resolved'] as int,
      session0Visible: json['session0_visible'] as int,
      servicesTotal: json['services_total'] as int,
      servicesWithPath: json['services_with_path'] as int,
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'elevated': elevated,
        'process_total': processTotal,
        'process_path_resolved': processPathResolved,
        'session0_visible': session0Visible,
        'services_total': servicesTotal,
        'services_with_path': servicesWithPath,
      };
}
