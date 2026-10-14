// lib/src/report/csv_report.dart
//
// CSV 报告。给 Excel 看 —— 拿到报告的人多半会先按某一列排一下序。
//
// 表头固定十列，顺序即契约：改列名或改顺序都会让下游的解析脚本静默错位。
// 换行用 \r\n（RFC 4180），因为 Excel 对纯 \n 的处理在部分区域设置下会串行。

import '../criteria/redact.dart';
import '../model/finding.dart';
import '../scan/orchestrator.dart';

const String kCsvHeader =
    'surface,criteria,locator,display_name,hidden,system,'
    'attributes_verified,covered,elevation_required,timestamp';

String toCsvReport(
  ScanResult result, {
  required String username,
  required String machineName,
}) {
  final StringBuffer out = StringBuffer();
  out.write(kCsvHeader);
  out.write('\r\n');

  for (final Finding f in result.findings) {
    final List<String> cells = <String>[
      f.surface,
      f.criteria,
      redactPath(f.locator, username: username, machineName: machineName),
      redactPath(f.displayName, username: username, machineName: machineName),
      f.hidden.toString(),
      f.system.toString(),
      f.attributesVerified.toString(),
      f.covered.toString(),
      f.elevationRequired.toString(),
      f.timestamp.toIso8601String(),
    ];
    out.write(cells.map(_escapeCsvCell).join(','));
    out.write('\r\n');
  }

  return out.toString();
}

/// RFC 4180：含逗号、双引号、CR 或 LF 的字段用双引号包起来，内部的双引号翻倍。
/// 路径里出现逗号是常事（`C:\Program Files\Foo, Inc\a.exe`），不转义就会整行错列。
String _escapeCsvCell(String cell) {
  final bool needsQuoting =
      cell.contains(',') || cell.contains('"') || cell.contains('\r') || cell.contains('\n');
  if (!needsQuoting) {
    return cell;
  }
  return '"${cell.replaceAll('"', '""')}"';
}
