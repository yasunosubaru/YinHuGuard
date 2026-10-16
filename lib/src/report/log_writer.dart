// lib/src/report/log_writer.dart
//
// 每次扫描写一份日志到 exe 旁边。这东西只有一个用途：**远程排障**。
// 工具是要拷给同事看的，出了问题时对方手里只有这份文件。
//
// 因此日志必须包含三类信息，缺一类对方就只能猜：
//   1) 自检结果 —— 这次扫描到底看到了多少（未提权时 Session 0 全是黑的）
//   2) 每个扫描面的条数 —— 是「这一面没命中」还是「这一面根本没跑成」
//   3) 每条未覆盖及其原因 —— 最容易被忽略、也最容易被误读成「干净」的部分
//
// 同样过一遍脱敏：日志和报告一样会离开这台机器。
// **不做崩溃自动上报** —— 安全工具向外发数据等于给攻击者留电话（spec §9.2）。

import 'dart:io';

import '../criteria/redact.dart';
import '../model/finding.dart';
import '../scan/orchestrator.dart';

/// 日志名用 ISO 时间戳，冒号换成连字符（Windows 文件名不允许冒号）。
String logFileNameFor(DateTime when) {
  final String stamp = when
      .toUtc()
      .toIso8601String()
      .split('.')
      .first
      .replaceAll(':', '-');
  return 'yinhuguard-$stamp.log';
}

Future<File> writeScanLog(
  ScanResult result,
  Directory outDir, {
  required String username,
  required String machineName,
}) async {
  final StringBuffer out = StringBuffer();

  out.writeln('YinHuGuard 扫描日志');
  out.writeln('开始: ${result.startedAt.toIso8601String()}');
  out.writeln('结束: ${result.finishedAt.toIso8601String()}');
  out.writeln('耗时: ${result.duration.inMilliseconds} ms');
  out.writeln();

  // ---- 1) 自检 ----
  out.writeln('== 自检 ==');
  final bool elevated = result.selfCheck.elevated;
  out.writeln('已提权: $elevated');
  out.writeln('进程总数: ${result.selfCheck.processTotal}');
  out.writeln('取到路径的进程: ${result.selfCheck.processPathResolved}');
  out.writeln('Session 0 可见进程: ${result.selfCheck.session0Visible}');
  out.writeln('服务总数: ${result.selfCheck.servicesTotal}');
  out.writeln('取到 ImagePath 的服务: ${result.selfCheck.servicesWithPath}');
  // 「不完整」只看**权限缺口**，与界面同源（selfcheck_panel 也是按
  // hasPermissionGap 判红）。这里原先是 `hasPermissionGap || 有未覆盖条目`，
  // 但残留进程恰恰会产出 covered=false 的发现 —— 于是同一份扫描，界面说
  // 「正常残留、不影响结论」，日志说「不能据此判断机器干净」。两边必须一致，
  // 否则读者不知道该信哪一个。
  //
  // 权限之外的未覆盖（注册表值的环境变量展不开、属性读不出）并没有因此丢掉：
  // 它们仍然逐条以 UNCOVERED 列出，并在下面写明各自的原因。
  if (result.selfCheck.hasPermissionGap) {
    out.writeln();
    out.writeln('!! 本次扫描的覆盖范围不完整。');
    if (!result.selfCheck.elevated) {
      out.writeln('!! 未提权，Session 0 的进程路径读不到，系统进程这一整块没有被检查。');
    }
    if (result.selfCheck.permissionGaps > 0) {
      out.writeln('!! 有 ${result.selfCheck.permissionGaps} 个进程/服务因权限没被检查。');
    }
    out.writeln('!! 不能据此判断机器干净。');
  }
  if (result.selfCheck.hasResidual) {
    // 刻意不算进「不完整」：扫描瞬间退出与保护进程是竞态，不是缺陷。
    // 把它们也算进去，这个日志就永远说「不完整」，警告也就废了。
    out.writeln('（另有 ${result.selfCheck.residualGaps} 个进程/服务在扫描期间退出或受保护，'
        '属正常现象，不影响结论。）');
  }
  out.writeln();

  // ---- 2) 每个面的条数 ----
  out.writeln('== 各扫描面 ==');
  for (final String surface in kScanOrder) {
    final int total = result.findings.where((Finding f) => f.surface == surface).length;
    final int uncovered =
        result.findings.where((Finding f) => f.surface == surface && !f.covered).length;
    out.writeln('$surface: $total 条（其中未覆盖 $uncovered 条）');
  }
  out.writeln();
  out.writeln('展开前发现总数: ${result.findings.length}');
  out.writeln('折叠进白名单: ${result.findings.where((Finding f) => f.allowlisted).length}');
  out.writeln();

  // ---- 3) 每条发现 + 未覆盖原因 ----
  out.writeln('== 发现 ==');
  for (final Finding f in result.findings) {
    final String locator = redactPath(f.locator, username: username, machineName: machineName);
    final String display =
        redactPath(f.displayName, username: username, machineName: machineName);
    final List<String> flags = <String>[
      f.surface,
      f.criteria,
      if (f.covered) 'covered' else 'UNCOVERED',
      if (f.hidden) 'H',
      if (f.system) 'S',
      // 已提权还 ACCESS_DENIED 的不是「需要提权」，是系统保护 —— 如实标注，
      // 否则用户在提权后的日志里读到自己已经做完的事，只会怀疑整个工具。
      if (f.elevationRequired) elevated ? 'protected' : 'needs-elevation',
      if (f.allowlisted) 'allowlisted',
    ];
    out.writeln('[${flags.join(' ')}] $locator');
    if (display.isNotEmpty && display != locator) {
      out.writeln('    -> $display');
    }
    if (!f.covered) {
      // 与界面同一套说法（findings_table 的 _uncoveredReason）：已提权时
      // 让用户「以管理员身份重跑」就是错的。
      if (f.elevationRequired && elevated) {
        out.writeln('    原因: 受系统保护，管理员权限也读不到（属正常残留）。');
      } else if (f.elevationRequired) {
        out.writeln('    原因: 权限不足，未能检查。需要以管理员身份重跑才能覆盖。');
      } else {
        out.writeln('    原因: 环境变量无法展开或数据不可读，未能判断文件是否存在。');
      }
    }
  }

  final File file = File('${outDir.path}${Platform.pathSeparator}${logFileNameFor(result.finishedAt)}');
  await file.writeAsString(out.toString());
  return file;
}
