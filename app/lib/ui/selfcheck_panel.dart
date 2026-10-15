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

import 'package:flutter/material.dart';

import 'package:yinhuguard_core/yinhuguard_core.dart';

import '../strings.dart';

class SelfCheckPanel extends StatelessWidget {
  final SelfCheck? selfCheck;

  /// 未覆盖条目数。面板不能只看 SelfCheck 的计数：自检计数是各面的聚合，
  /// 而某一条具体项读不出来时那是发现级的证据，聚合数字上看不出来。
  final int uncoveredCount;

  final bool elevateAttempted;
  final VoidCallback? onElevate;

  const SelfCheckPanel({
    super.key,
    required this.selfCheck,
    this.uncoveredCount = 0,
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

    final bool incomplete = check.coverageIncomplete(uncoveredCount);

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
                  // 这个数字是 0 而没提权，就是「系统进程完全没看」。
                  alert: incomplete,
                ),
                _Stat(label: kServicesTotal, value: '${check.servicesTotal}'),
                _Stat(label: kServicesWithPath, value: '${check.servicesWithPath}'),
              ],
            ),
            if (incomplete) ...<Widget>[
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
                      // 未提权是原因里最要紧的一种，单独给一段具体说法；
                      // 已提权却仍有条目没检查出来时，用通用那段。
                      check.elevated ? kUnresolvedRowsBody : kSession0WarningBody,
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
            ] else if (check.coverageComplete) ...<Widget>[
              const SizedBox(height: 8),
              Text(
                kElevatedAlready,
                style: theme.textTheme.bodySmall,
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
