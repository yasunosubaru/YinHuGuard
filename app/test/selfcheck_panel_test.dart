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
  int knownCount = 0,
  int unidentifiedCount = 0,
}) {
  return tester.pumpWidget(
    MaterialApp(
      home: Scaffold(
        body: SelfCheckPanel(
          selfCheck: check,
          uncoveredCount: uncoveredCount,
          knownCount: knownCount,
          unidentifiedCount: unidentifiedCount,
        ),
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

  testWidgets('未提权 + 权限缺口 → 红色不完整警告，且不给分诊摘要',
      (WidgetTester tester) async {
    await pumpPanel(
      tester,
      check: sc(elevated: false, processUnresolvedPermission: 258),
      uncoveredCount: 117,
      knownCount: 24,
      unidentifiedCount: 93,
    );

    expect(find.text(kCoverageIncompleteTitle), findsOneWidget);
    expect(find.text(kSession0WarningBody), findsOneWidget);
    expect(find.text(kCoverageCompleteTitle), findsNothing);
    expect(find.text(kCoverageReachedTitle), findsNothing);
    // 未提权时那些「名字对不上」全是没提权造成的，不能当线索给出去。
    expect(find.textContaining('待人工核实'), findsNothing);
  });

  testWidgets('枚举失败 → 显式报「自检异常」，不能让空列表冒充干净',
      (WidgetTester tester) async {
    await pumpPanel(tester, check: sc(processTotal: 0));

    expect(find.text(kSelfCheckFailedTitle), findsOneWidget);
    expect(find.text(kSelfCheckFailedBody), findsOneWidget);
    expect(find.text(kCoverageIncompleteTitle), findsNothing);
    expect(find.text(kCoverageReachedTitle), findsNothing);
  });

  testWidgets('有未覆盖条目 → 给分诊摘要：多少条已对照、多少条待人工核实',
      (WidgetTester tester) async {
    // 用户实测的规模：38 条未覆盖（26 进程 + 12 驱动）。
    await pumpPanel(
      tester,
      check: sc(processUnresolvedOther: 48),
      uncoveredCount: 38,
      knownCount: 37,
      unidentifiedCount: 1,
    );

    expect(find.textContaining('已对照已知组件 37 条'), findsOneWidget);
    expect(find.textContaining('待人工核实 1 条'), findsOneWidget);
    // 摘要不是警告：颜色是中性色，红色留给列表里那一条。
    expect(find.text(kCoverageReachedTitle), findsOneWidget);
    expect(find.text(kCoverageIncompleteTitle), findsNothing);
  });

  testWidgets('清单缺失（knownCount 为 0）→ 不显示「已对照 0 条」这种废话',
      (WidgetTester tester) async {
    await pumpPanel(tester, check: sc(), uncoveredCount: 3);

    expect(find.textContaining('已对照已知组件'), findsNothing);
    expect(find.textContaining('待人工核实'), findsNothing);
  });
}
