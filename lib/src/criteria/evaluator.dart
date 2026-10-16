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
import '../triage/known_components.dart';

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
///
/// [knownComponents] 给未覆盖条目做名字对照（分诊用，见
/// triage/known_components.dart）。它只写进 [Finding.known]，不参与任何判定。
List<Finding> evaluate(
  List<Observation> observations, {
  required List<String> userAllowlist,
  KnownComponents knownComponents = const KnownComponents(),
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
        // 未覆盖条目才对照：已覆盖的条目路径都读到了，判据已经给过答案，
        // 再贴一个「名字眼熟」只会稀释真正的信号。
        known: observation.covered
            ? null
            : knownComponents.lookup(
                  observation.surface,
                  observation.displayName,
                ) ??
                knownComponents.lookup(
                  observation.surface,
                  observation.locator,
                ),
        // 三个占位字段一期恒为 null，显式写出来是为了让二期改动点只有一个。
        confidence: null,
        suggestedAction: null,
        changeRecord: null,
      ),
  ];
}

/// 未覆盖条目数。界面与报告都要以它为准说明「这次没看到什么」。
int uncoveredCountOf(List<Finding> findings) =>
    findings.where((Finding f) => !f.covered).length;

/// 未覆盖条目里已对照上已知组件的条数。
int knownCountOf(List<Finding> findings) =>
    findings.where((Finding f) => !f.covered && f.known != null).length;

/// 未覆盖条目里没能对照上、需要人看一眼的条数。
///
/// 这是整份报告里**唯一**值得优先读的数字：其余未覆盖都已经能给出名字层面的
/// 解释，只有这些连名字都对不上。
int unidentifiedCountOf(List<Finding> findings) =>
    findings.where((Finding f) => !f.covered && f.known == null).length;
