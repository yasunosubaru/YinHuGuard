// lib/src/criteria/redact.dart
//
// 报告脱敏。规则只有一条，但两个方向的取舍都要说清楚：
//
//   替换：本机用户名、机器名 → <USER> / <MACHINE>
//     理由：用户名 + 机器名组合起来能定位到具体的人。报告是要发给同事看的，
//     这件事不该由使用者自己记得去手改。
//
//   保留：文件路径的其余部分，一个字符都不动
//     理由：「这文件到底在哪」是远程帮你看的那个人判断该不该动手的唯一依据。
//     把路径也脱敏掉，报告就只剩「发现了 3 项」，等于没给。
//
// 不做路径规范化：Program Files 里的空格、8.3 短名、大小写都原样保留 ——
// 任何"顺手规整一下"都会让报告里的路径和用户机器上的路径对不上。

/// 把 [raw] 里的本机用户名与机器名换成占位符。
///
/// [username] 或 [machineName] 为空串时跳过该项替换 —— 空串会匹配任何位置，
/// 把整条路径切碎。
String redactPath(
  String raw, {
  required String username,
  required String machineName,
}) {
  String out = raw;
  // 先机器名再用户名：机器名通常更长也更具体，先换掉可以减少后续误替换的窗口。
  if (machineName.isNotEmpty) {
    out = _replaceAllCaseInsensitive(out, machineName, '<MACHINE>');
  }
  if (username.isNotEmpty) {
    out = _replaceAllCaseInsensitive(out, username, '<USER>');
  }
  return out;
}

String _replaceAllCaseInsensitive(String haystack, String needle, String replacement) {
  if (needle.isEmpty) {
    return haystack;
  }
  // 用带字面转义的 RegExp 而不是 String.replaceAll：后者区分大小写，
  // 而 Windows 的用户名与机器名在实际路径里大小写并不稳定。
  final RegExp pattern = RegExp(RegExp.escape(needle), caseSensitive: false);
  return haystack.replaceAll(pattern, replacement);
}
