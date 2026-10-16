// app/test/selfcheck_panel_test.dart
//
// 自检面板四档状态的回归。四档互斥、永不同屏：
//   枚举失败（红）→ 权限缺口（红）→ 覆盖完整（蓝）→ 已提权常态（肯定）
//
// 用户实测报过「蓝色覆盖完整 + 红色未覆盖 28 条同屏」。
// 这里逐条钉死：完整还要求发现级零未覆盖；已提权时给常驻肯定结论；
// 枚举失败绝不能悄悄放过去。

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yinhuguard_app/strings.dart';
import 'package:yinhuguard_app/ui/selfcheck_panel.dart';
import 'package:yinhuguard_core/yinhuguard_core.dart';

SelfCheck sc({
  bool elevated = true,
  int processTotal = 690,
  int servicesTotal = 360,
  int processUnresolvedPermission = 0,
  int processUnresolvedOther = 0,
  int servicesUnresolvedPermission = 0,
  int servicesUnresolvedOther = 0,
}) =>
    SelfCheck(
      elevated: elevated,
      processTotal: processTotal,
      processPathResolved: processTotal -
          processUnresolvedPermission -
          processUnresolvedOther,
      session0Visible: elevated ? 220 : 0,
      servicesTotal: servicesTotal,
      servicesWithPath:
          servicesTotal - servicesUnresolvedPermission - servicesUnresolvedOther,
      processUnresolvedPermission: processUnresolvedPermission,
      processUnresolvedOther: processUnresolvedOther,
      servicesUnresolvedPermission: servicesUnresolvedPermission,
      servicesUnresolvedOther: servicesUnresolvedOther,
    );

Future<void> pumpPanel(
  WidgetTester tester, {
  required SelfCheck check,
  int uncoveredCount = 0,
}) {
  return tester.pumpWidget(
    MaterialApp(
      home: Scaffold(
        body: SelfCheckPanel(selfCheck: check, uncoveredCount: uncoveredCount),
      ),
    ),
  );
}

void main() {
  testWidgets('已提权 + 残留 + 无未覆盖条目 → 肯定结论，绝不出现「覆盖完整」',
      (WidgetTester tester) async {
    await pumpPanel(tester, check: sc(processUnresolvedOther: 2));

    expect(find.text(kCoverageReachedTitle), findsOneWidget);
    expect(find.textContaining('另有 2 个'), findsOneWidget);
    expect(find.text(kCoverageReachedBodyWithList), findsNothing);
    expect(find.text(kCoverageCompleteTitle), findsNothing);
    expect(find.text(kCoverageIncompleteTitle), findsNothing);
  });

  testWidgets('已提权 + 零缺口 + 零未覆盖 → 覆盖完整', (WidgetTester tester) async {
    await pumpPanel(tester, check: sc());

    expect(find.text(kCoverageCompleteTitle), findsOneWidget);
    expect(find.text(kCoverageReachedTitle), findsNothing);
    expect(find.text(kCoverageIncompleteTitle), findsNothing);
  });

  testWidgets('已提权 + 零缺口 + 有未覆盖条目 → 不报完整，指给下方列表',
      (WidgetTester tester) async {
    // 自检计数全零，但发现级有未覆盖（驱动、注册表这些面没有自检计数）。
    // 「蓝色覆盖完整 + 红色未覆盖」同屏就是从这里漏出来的。
    await pumpPanel(tester, check: sc(), uncoveredCount: 3);

    expect(find.text(kCoverageCompleteTitle), findsNothing);
    expect(find.text(kCoverageReachedTitle), findsOneWidget);
    expect(find.textContaining('已在下方逐条标为「未覆盖」'), findsOneWidget);
  });

  testWidgets('未提权 + 权限缺口 → 红色不完整警告', (WidgetTester tester) async {
    await pumpPanel(
      tester,
      check: sc(elevated: false, processUnresolvedPermission: 258),
    );

    expect(find.text(kCoverageIncompleteTitle), findsOneWidget);
    expect(find.text(kSession0WarningBody), findsOneWidget);
    expect(find.text(kCoverageCompleteTitle), findsNothing);
    expect(find.text(kCoverageReachedTitle), findsNothing);
  });

  testWidgets('枚举失败 → 显式报「自检异常」，不能让空列表冒充干净',
      (WidgetTester tester) async {
    await pumpPanel(tester, check: sc(processTotal: 0));

    expect(find.text(kSelfCheckFailedTitle), findsOneWidget);
    expect(find.text(kSelfCheckFailedBody), findsOneWidget);
    expect(find.text(kCoverageIncompleteTitle), findsNothing);
    expect(find.text(kCoverageReachedTitle), findsNothing);
  });
}
