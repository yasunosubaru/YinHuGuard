// app/lib/ui/selfcheck_panel.dart
//
// 自检面板。**这是整个界面最重要的一块**，因为它是唯一挡住那个致命误读的地方：
// 未提权时 Session 0 的进程路径一条都拿不到，于是「什么都没查到」听起来
// 像是「机器是干净的」。
//
// 所以：
//   * session0_visible == 0 且未提权 → 必须显示醒目的未覆盖警告
//   * 警告正文必须写明「不等于机器干净」，而不是只给一个数字
//   * 提权按钮在被取消过一次之后禁用，并说明原因，避免无限弹 UAC
//   * 已提权且权限零缺口 → 必须给常驻的肯定结论（真机上这就是常态），
//     但**不能出现「完整」二字**：列表里仍有「未覆盖」条目，
//     「覆盖完整 + 未覆盖同屏」正是用户实测报过的自相矛盾

import 'package:flutter/material.dart';

import 'package:yinhuguard_core/yinhuguard_core.dart';

import '../strings.dart';

class SelfCheckPanel extends StatelessWidget {
  final SelfCheck? selfCheck;

  /// 未覆盖条目数。面板不能只看 SelfCheck 的计数：自检计数是各面的聚合，
  /// 而某一条具体项读不出来时那是发现级的证据，聚合数字上看不出来。
  final int uncoveredCount;

  /// 未覆盖里已对照上已知组件的条数 / 没能对照上、需人工核实的条数。
  /// 分诊摘要用；两者都为 0 时不显示摘要（清单缺失时不该显示「已对照 0 条」）。
  final int knownCount;
  final int unidentifiedCount;

  final bool elevateAttempted;
  final VoidCallback? onElevate;

  const SelfCheckPanel({
    super.key,
    required this.selfCheck,
    this.uncoveredCount = 0,
    this.knownCount = 0,
    this.unidentifiedCount = 0,
    this.elevateAttempted = false,
    this.onElevate,
  });

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final SelfCheck? check = selfCheck;

    if (check == null) {
      return const SizedBox.shrink();
    }

    final bool abnormal = check.enumerationDead;
    final bool incomplete = check.hasPermissionGap;
    final bool residual = check.hasResidual;
    // 「覆盖完整」还要求发现级零未覆盖：自检计数是各面的聚合，驱动、注册表
    // 这些面根本没有自检计数 —— 只看聚合数字就会放出「蓝色覆盖完整 +
    // 红色未覆盖 28 条」同屏，那正是用户报上来的自相矛盾。
    final bool complete = check.coverageComplete && uncoveredCount == 0;
    // 已提权、权限零缺口但还够不着「完整」：真机常态，给常驻的肯定结论。
    final bool reached = check.coverageReached && !complete;

    return Card(
      margin: const EdgeInsets.all(12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(kSelfCheckTitle, style: theme.textTheme.titleSmall),
            const SizedBox(height: 8),
            Wrap(
              spacing: 20,
              runSpacing: 6,
              children: <Widget>[
                _Stat(label: kElevated, value: check.elevated ? kYes : kNo),
                _Stat(label: kProcessTotal, value: '${check.processTotal}'),
                _Stat(label: kProcessPathResolved, value: '${check.processPathResolved}'),
                _Stat(
                  label: kSession0Visible,
                  value: '${check.session0Visible}',
                  // 这个数字是 0 而没提权，就是「系统进程完全没看」；
                  // 枚举整个失败时它同样该红。
                  alert: incomplete || abnormal,
                ),
                _Stat(label: kServicesTotal, value: '${check.servicesTotal}'),
                _Stat(label: kServicesWithPath, value: '${check.servicesWithPath}'),
              ],
            ),
            if (incomplete)
              Padding(
                padding: const EdgeInsets.only(top: 6),
                child: Text(
                  '因权限未检查：${check.permissionGaps} 个',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.error,
                  ),
                ),
              ),
            if (residual)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Text(
                  '扫描期退出/受保护：${check.residualGaps} 个（正常）',
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.outline,
                  ),
                ),
              ),
            // 未覆盖的规模与分诊结果。**中性色**：这一行不是警告，是
            // 「哪几条要人看」的指针；真正需要人看的那条在列表里自带红色标记。
            if (uncoveredCount > 0 && knownCount > 0 && check.elevated)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Text(
                  kUncoveredTriage(uncoveredCount, knownCount, unidentifiedCount),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.outline,
                  ),
                ),
              ),
            // 三档互斥、按严重度排序，永远不会同屏：
            //   枚举失败（结果不可用）→ 权限缺口（红，可行动）→ 肯定结论（蓝/已提权）
            if (abnormal) ...<Widget>[
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.errorContainer,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Row(
                      children: <Widget>[
                        Icon(Icons.error_outline,
                            color: theme.colorScheme.onErrorContainer),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            kSelfCheckFailedTitle,
                            style: theme.textTheme.titleSmall?.copyWith(
                              color: theme.colorScheme.onErrorContainer,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      kSelfCheckFailedBody,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onErrorContainer,
                      ),
                    ),
                  ],
                ),
              ),
            ] else if (incomplete) ...<Widget>[
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.errorContainer,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Row(
                      children: <Widget>[
                        Icon(Icons.warning_amber,
                            color: theme.colorScheme.onErrorContainer),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            kCoverageIncompleteTitle,
                            style: theme.textTheme.titleSmall?.copyWith(
                              color: theme.colorScheme.onErrorContainer,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      // incomplete 只可能是「未提权」：权限缺口按提权状态分类，
                      // 已提权时读不到的条目一律归残留，走下面「已提权」那一档。
                      kSession0WarningBody,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onErrorContainer,
                      ),
                    ),
                    const SizedBox(height: 8),
                    if (onElevate != null)
                      FilledButton.tonal(
                        // 已经提权过一次仍未成功 → 用户取消了 UAC，别再弹。
                        onPressed: elevateAttempted ? null : onElevate,
                        child: Text(kElevateButton),
                      ),
                    if (elevateAttempted)
                      Padding(
                        padding: const EdgeInsets.only(top: 6),
                        child: Text(
                          kElevateCancelled,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onErrorContainer,
                          ),
                        ),
                      ),
                  ],
                ),
              ),
] else if (complete) ...<Widget>[
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.secondaryContainer,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Row(
                      children: <Widget>[
                        Icon(Icons.verified_outlined,
                            color: theme.colorScheme.onSecondaryContainer),
                        const SizedBox(width: 8),
                        Text(
                          kCoverageCompleteTitle,
                          style: theme.textTheme.titleSmall?.copyWith(
                            color: theme.colorScheme.onSecondaryContainer,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      kCoverageCompleteBody,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSecondaryContainer,
                      ),
                    ),
                  ],
                ),
              ),
            ] else if (reached) ...<Widget>[
              // 「已提权」这一档是真机常态。它不是缺陷，所以绝不能报红 ——
              // 红色一旦给错了地方，用户就会对整块面板失去信任，连带不再看
              // 真正该看的权限缺口。一个永远关不掉的警告等于没有警告。
              const SizedBox(height: 12),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.secondaryContainer,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    Row(
                      children: <Widget>[
                        Icon(Icons.check_circle_outline,
                            color: theme.colorScheme.onSecondaryContainer),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            kCoverageReachedTitle,
                            style: theme.textTheme.titleSmall?.copyWith(
                              color: theme.colorScheme.onSecondaryContainer,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      // 有发现级未覆盖（列表里看得到）就指给列表；只有自检
                      // 残留时说明它们没有留下可列出的条目。
                      uncoveredCount > 0
                          ? kCoverageReachedBodyWithList
                          : kCoverageReachedBodyResidualOnly
                              .replaceAll('%d', '${check.residualGaps}'),
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSecondaryContainer,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _Stat extends StatelessWidget {
  final String label;
  final String value;
  final bool alert;
  const _Stat({required this.label, required this.value, this.alert = false});

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: <Widget>[
        Text(label, style: theme.textTheme.bodySmall),
        Text(
          value,
          style: theme.textTheme.titleMedium?.copyWith(
            color: alert ? theme.colorScheme.error : null,
            fontWeight: alert ? FontWeight.bold : null,
          ),
        ),
      ],
    );
  }
}
