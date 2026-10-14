// lib/src/criteria/evaluator.dart
//
// 把观测变成发现。这一层刻意做得很薄：不排序、不去重、不过滤，
// 只判一件事 —— 这条观测是否命中白名单。
//
// 不做过滤是刻意的。上游 bat 的毛病之一就是「读不到就静默丢掉」，
// 而丢掉之后界面上什么都看不出来。这里保持「观测进、发现出」的一一对应，
// 让「未覆盖」这类事实一路活到报告里。

import '../model/finding.dart';
import '../model/observation.dart';

/// 取路径的最后一段（同时接受 `\` 和 `/`）。
String basenameOf(String path) {
  final int cut = path.lastIndexOf(RegExp(r'[\\/]'));
  return cut < 0 ? path : path.substring(cut + 1);
}

/// 逐条判定白名单折叠。
///
/// [userAllowlist] 里的项按**文件名**匹配（大小写不敏感），不按完整路径 ——
/// 用户把它加白时的心理单位是「explorer.exe 是正常的」，而不是某个绝对路径；
/// 换台机器换盘符就不该失效。
///
/// 未覆盖（covered == false）的条目**永不折叠**，也不丢弃。
List<Finding> evaluate(
  List<Observation> observations, {
  required List<String> userAllowlist,
}) {
  final Set<String> allow = <String>{
    for (final String entry in userAllowlist) entry.toLowerCase(),
  };

  return <Finding>[
    for (final Observation observation in observations)
      Finding(
        observation,
        allowlisted: observation.covered &&
            allow.contains(basenameOf(observation.locator).toLowerCase()),
        // 三个占位字段一期恒为 null，显式写出来是为了让二期改动点只有一个。
        confidence: null,
        suggestedAction: null,
        changeRecord: null,
      ),
  ];
}

/// 未覆盖的条目数。界面与报告都要以它为准说明「这次没看到什么」。
int uncoveredCount(List<Finding> findings) =>
    findings.where((Finding f) => !f.covered).length;
