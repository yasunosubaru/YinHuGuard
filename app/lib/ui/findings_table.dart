// app/lib/ui/findings_table.dart
//
// 结果明细表。默认按扫描面分组、组内按时间倒序（spec §7）。
//
// 一期不做颜色分级 —— Q2 选了「照搬原脚本只看 H/S 属性」，所有命中在判据上
// 是等价的，硬加一个严重度反而是在暗示一个我们并不掌握的信息。
// 因此分组与标记文字是仅有的两个扫读辅助。
//
// 白名单折叠的条目**保留并标出**，不隐藏：用户要能回头看自己白掉了什么。

import 'package:flutter/material.dart';

import 'package:yinhuguard_core/yinhuguard_core.dart';

import '../strings.dart';
import 'sidebar_tree.dart';

class FindingsTable extends StatelessWidget {
  /// 已按扫描面筛过的发现（selected 为 null 时是全部）。
  final List<Finding> findings;

  /// 本次扫描是否已提权。行内措辞与颜色都取决于它：已提权时还会
  /// ACCESS_DENIED 的只能是系统保护（PPL），再说「需要提权」就是错的。
  final bool elevated;

  const FindingsTable({
    super.key,
    required this.findings,
    this.elevated = false,
  });

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);

    if (findings.isEmpty) {
      return Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Text(kEmptyForSurface, style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            // 任何「没有命中」的表述都必须紧跟这句，否则会被读成「没问题」。
            Text(
              kEmptyCaveat,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.error,
              ),
            ),
          ],
        ),
      );
    }

    // 分组：按 kSurfaceEntries 的固定顺序，组内时间倒序。
    final Map<String, List<Finding>> grouped = <String, List<Finding>>{};
    for (final Finding finding in findings) {
      grouped.putIfAbsent(finding.surface, () => <Finding>[]).add(finding);
    }
    for (final List<Finding> group in grouped.values) {
      group.sort((Finding a, Finding b) => b.timestamp.compareTo(a.timestamp));
    }

    final List<Widget> sections = <Widget>[];
    for (final SurfaceEntry entry in kSurfaceEntries) {
      final List<Finding>? group = grouped[entry.key];
      if (group == null || group.isEmpty) {
        continue;
      }
      sections.add(_GroupHeader(label: entry.label, count: group.length));
      for (final Finding finding in group) {
        sections.add(_FindingTile(finding: finding, elevated: elevated));
      }
    }

    return ListView(
      padding: const EdgeInsets.symmetric(vertical: 8),
      children: sections,
    );
  }
}

class _GroupHeader extends StatelessWidget {
  final String label;
  final int count;
  const _GroupHeader({required this.label, required this.count});

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    return Container(
      color: theme.colorScheme.surfaceContainerHighest,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Text('$label  ·  $count 条', style: theme.textTheme.titleSmall),
    );
  }
}

class _FindingTile extends StatelessWidget {
  final Finding finding;
  final bool elevated;
  const _FindingTile({required this.finding, required this.elevated});

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);

    // 可行动缺口 = 未提权且被拒。已提权时读不到的一律是系统保护/竞态，
    // 不是缺陷 —— 那些条目若继续用错误色，「提权后仍一片红」就会重演。
    final bool actionableGap = !finding.covered && !elevated;

    // 名字对不上已知清单的那一两条，才是真正需要人看的。它自带颜色，
    // 不跟着整行走 —— 已提权时整行是中性色，但这一条必须跳出来。
    //
    // **只在已提权视图里谈身份**：未提权时「读不到」的原因就是没提权，
    // 一百多条无辜的服务进程都会被算成「名字对不上」，那是纯粹的噪声。
    final bool needsReview = elevated && !finding.covered && finding.known == null;

    final List<String> badges = <String>[
      kCriteriaLabels[finding.criteria] ?? finding.criteria,
      if (!finding.covered) kUncoveredBadge,
      if (finding.hidden) kHiddenBadge,
      if (finding.system) kSystemBadge,
      if (finding.elevationRequired) elevated ? kProtectedBadge : kNeedsElevationBadge,
      if (finding.allowlisted) kAllowlistedBadge,
      // 自动对照结果（只按名字，见 triage/known_components.dart）。
      if (needsReview)
        kUnidentifiedBadge
      else if (elevated && !finding.covered)
        finding.known!.isWindows ? kKnownWindowsBadge : kKnownVendorBadge,
    ];

    return Opacity(
      // 折叠的条目不隐藏，只是弱化。
      opacity: finding.allowlisted ? 0.55 : 1.0,
      child: ListTile(
        dense: true,
        leading: finding.covered
            ? Icon(Icons.report, color: theme.colorScheme.error)
            : Icon(Icons.help_outline, color: theme.colorScheme.outline),
        title: Text(
          finding.locator,
          style: theme.textTheme.bodyMedium?.copyWith(
            fontFamily: 'monospace',
          ),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            if (finding.displayName.isNotEmpty && finding.displayName != finding.locator)
              Text(
                '$kColumnDisplayName: ${finding.displayName}',
                style: theme.textTheme.bodySmall?.copyWith(fontFamily: 'monospace'),
              ),
            const SizedBox(height: 2),
            Wrap(
              spacing: 6,
              runSpacing: 2,
              children: <Widget>[
                for (final String badge in badges)
                  _Badge(
                    text: badge,
                    // 未覆盖用错误色：它是「没看」而不是「看了没问题」；
                    // 已提权时读不到的不再可行动，改用中性色。
                    emphasis: !finding.covered || finding.allowlisted,
                    bad: actionableGap || needsReview,
                  ),
              ],
            ),
            if (!finding.covered)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(
                  // 与日志同一套说法（log_writer 的原因行）。
                  _uncoveredReason(finding, elevated: elevated),
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: actionableGap || needsReview
                        ? theme.colorScheme.error
                        : theme.colorScheme.outline,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

/// 未覆盖条目的行内原因 + 名字对照结果。与日志同一套说法：已提权时让用户
/// 「以管理员身份重跑」就是错的 —— 那正是他刚刚做完的事。
String _uncoveredReason(Finding finding, {required bool elevated}) {
  if (!elevated) {
    return finding.elevationRequired
        ? kUncoveredNeedsElevation
        : kUncoveredDataUnreadable;
  }
  final String why =
      finding.elevationRequired ? kUncoveredProtected : kUncoveredNoEvidence;
  // 身份只在已提权视图里谈：未提权时读不到的原因是权限，不是身份。
  final KnownComponent? known = finding.known;
  final String triage = known == null
      ? kUnidentifiedNote
      : (known.isWindows ? kKnownWindowsNote : kKnownVendorNote);
  return '$why $triage';
}

class _Badge extends StatelessWidget {
  final String text;
  final bool emphasis;
  final bool bad;
  const _Badge({required this.text, this.emphasis = false, this.bad = false});

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final Color fg = bad
        ? theme.colorScheme.error
        : emphasis
            ? theme.colorScheme.onSurfaceVariant
            : theme.colorScheme.onSurface;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        border: Border.all(color: fg.withValues(alpha: 0.5)),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(text, style: theme.textTheme.labelSmall?.copyWith(color: fg)),
    );
  }
}
