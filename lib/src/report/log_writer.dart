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

import '../criteria/evaluator.dart';
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
  if (result.selfCheck.coverageIncomplete(uncoveredCountOf(result.findings))) {
    out.writeln();
    out.writeln('!! 本次扫描的覆盖范围不完整。');
    if (!result.selfCheck.elevated) {
      out.writeln('!! 未提权，Session 0 的进程路径读不到，系统进程这一整块没有被检查。');
    }
    if (result.selfCheck.hasUnresolvedProcesses) {
      out.writeln('!! 有 ${result.selfCheck.processTotal - result.selfCheck.processPathResolved} '
          '个进程取不到路径，它们没有被检查。');
    }
    if (result.selfCheck.hasUnresolvedServices) {
      out.writeln('!! 有 ${result.selfCheck.servicesTotal - result.selfCheck.servicesWithPath} '
          '个服务取不到 ImagePath，它们没有被检查。');
    }
    out.writeln('!! 不能据此判断机器干净。');
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
      if (f.elevationRequired) 'needs-elevation',
      if (f.allowlisted) 'allowlisted',
    ];
    out.writeln('[${flags.join(' ')}] $locator');
    if (display.isNotEmpty && display != locator) {
      out.writeln('    -> $display');
    }
    if (!f.covered) {
      out.writeln(f.elevationRequired
          ? '    原因: 权限不足，未能检查。需要以管理员身份重跑才能覆盖。'
          : '    原因: 环境变量无法展开或数据不可读，未能判断文件是否存在。');
    }
  }

  final File file = File('${outDir.path}${Platform.pathSeparator}${logFileNameFor(result.finishedAt)}');
  await file.writeAsString(out.toString());
  return file;
}
