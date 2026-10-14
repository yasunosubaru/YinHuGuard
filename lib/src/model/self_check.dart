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

  /// 未提权且拿不到任何 Session 0 进程路径 —— 界面必须据此显示未覆盖提示。
  bool get sessionZeroUncovered => !elevated && session0Visible == 0;

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
