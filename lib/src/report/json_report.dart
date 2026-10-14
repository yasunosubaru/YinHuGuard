// lib/src/report/json_report.dart
//
// JSON 报告。给下一段程序读，也给人看。
//
// 两条硬要求：
//   1) 每个 locator / display_name 序列化前一律过一遍 redactPath —— 报告是要
//      发出去的东西，脱敏不能靠使用者记得手改（spec §9.1）。
//   2) **必须**写出 uncovered_count 与完整的 self_check。只报「发现了什么」而
//      不报「没看到什么」，正是上游 bat 那个 `2^>nul` 的错误放大版。

import 'dart:convert';

import '../criteria/redact.dart';
import '../model/finding.dart';
import '../scan/orchestrator.dart';

const int kReportSchemaVersion = 1;

/// 由 ScanResult 生成 JSON 文本。[username] / [machineName] 用于脱敏。
String toJsonReport(
  ScanResult result, {
  required String username,
  required String machineName,
}) {
  int uncovered = 0;
  final List<Map<String, dynamic>> findings = <Map<String, dynamic>>[];

  for (final Finding f in result.findings) {
    if (!f.covered) {
      uncovered += 1;
    }
    findings.add(<String, dynamic>{
      'surface': f.surface,
      'criteria': f.criteria,
      'locator': redactPath(f.locator, username: username, machineName: machineName),
      'display_name':
          redactPath(f.displayName, username: username, machineName: machineName),
      'hidden': f.hidden,
      'system': f.system,
      'attributes_verified': f.attributesVerified,
      'covered': f.covered,
      'elevation_required': f.elevationRequired,
      'allowlisted': f.allowlisted,
      'timestamp': f.timestamp.toIso8601String(),
      // 二期占位字段：一期恒为 null，但键**必须存在**，
      // 这样二期填值不会让报告格式变化。
      'confidence': f.confidence,
      'suggested_action': f.suggestedAction,
      'change_record': f.changeRecord,
    });
  }

  final Map<String, dynamic> report = <String, dynamic>{
    'schema_version': kReportSchemaVersion,
    'started_at': result.startedAt.toIso8601String(),
    'finished_at': result.finishedAt.toIso8601String(),
    'duration_ms': result.duration.inMilliseconds,
    'self_check': result.selfCheck.toJson(),
    // 名字刻意不叫 covered_count：读者需要的是「有多少条没看」，而不是
    // 「有多少条看到了」——后者在干净机器上恒等于发现总数，不加信息量。
    'uncovered_count': uncovered,
    'findings': findings,
  };

  return const JsonEncoder.withIndent('  ').convert(report);
}
