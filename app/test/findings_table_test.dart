// app/test/findings_table_test.dart
//
// 行级措辞的回归：
//   * 已提权时不允许再出现「需要提权」/「以管理员身份重跑」
//     —— 用户第一条反馈就是「我已经给了最高权限，为什么还写着要提权」；
//   * 未覆盖条目要带上名字对照结果（已知组件 / 待人工核实）
//     —— 用户第二条反馈是「还是有未覆盖的 26 项和 12 项啊」，
//       数字没法消掉，但必须看得出哪几条要人看。

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yinhuguard_app/strings.dart';
import 'package:yinhuguard_app/ui/findings_table.dart';
import 'package:yinhuguard_core/yinhuguard_core.dart';

Finding uncoveredProcess({
  required bool elevationRequired,
  KnownComponent? known,
  String name = 'csrss.exe',
}) =>
    Finding(
      Observation(
        surface: 'processes',
        locator: name,
        displayName: name,
        criteria: 'file_attr_hs',
        attributesVerified: false,
        hidden: false,
        system: false,
        elevationRequired: elevationRequired,
        covered: false,
        timestamp: DateTime.utc(2026, 1, 1),
      ),
      allowlisted: false,
      known: known,
    );

Future<void> pumpTable(
  WidgetTester tester, {
  required Finding finding,
  required bool elevated,
}) {
  return tester.pumpWidget(
    MaterialApp(
      home: Scaffold(
        body: FindingsTable(findings: <Finding>[finding], elevated: elevated),
      ),
    ),
  );
}

void main() {
  testWidgets('已提权 + 已知系统组件：系统保护 + 「已知系统组件」标记',
      (WidgetTester tester) async {
    await pumpTable(
      tester,
      finding: uncoveredProcess(
        elevationRequired: true,
        known: const KnownComponent(KnownKind.windows, 'Windows 系统组件'),
      ),
      elevated: true,
    );

    expect(find.text(kProtectedBadge), findsOneWidget);
    expect(find.text(kUncoveredBadge), findsOneWidget);
    expect(find.text(kKnownWindowsBadge), findsOneWidget);
    expect(find.textContaining(kUncoveredProtected), findsOneWidget);
    expect(find.textContaining(kKnownWindowsNote), findsOneWidget);
    expect(find.text(kUnidentifiedBadge), findsNothing);
    expect(find.text(kNeedsElevationBadge), findsNothing);
    expect(find.textContaining(kUncoveredNeedsElevation), findsNothing);
  });

  testWidgets('已提权 + 名字对不上：标「待人工核实」并给出核实指引',
      (WidgetTester tester) async {
    await pumpTable(
      tester,
      finding: uncoveredProcess(elevationRequired: true, name: 'iGoSwServer.exe'),
      elevated: true,
    );

    expect(find.text(kUnidentifiedBadge), findsOneWidget);
    expect(find.textContaining(kUnidentifiedNote), findsOneWidget);
    expect(find.text(kKnownWindowsBadge), findsNothing);
    expect(find.text(kKnownVendorBadge), findsNothing);
  });

  testWidgets('已提权 + 已识别第三方：标记带厂商归属，不冒充 Windows 组件',
      (WidgetTester tester) async {
    await pumpTable(
      tester,
      finding: uncoveredProcess(
        elevationRequired: true,
        known: const KnownComponent(KnownKind.vendor, 'Intel PresentMon（性能监测）'),
        name: 'PresentMonService.exe',
      ),
      elevated: true,
    );

    expect(find.text(kKnownVendorBadge), findsOneWidget);
    expect(find.textContaining(kKnownVendorNote), findsOneWidget);
    expect(find.text(kKnownWindowsBadge), findsNothing);
    expect(find.text(kUnidentifiedBadge), findsNothing);
  });

  testWidgets('未提权：仍然写「需要提权」并给出重跑指引',
      (WidgetTester tester) async {
    await pumpTable(
      tester,
      finding: uncoveredProcess(elevationRequired: true),
      elevated: false,
    );

    expect(find.text(kNeedsElevationBadge), findsOneWidget);
    expect(find.textContaining(kUncoveredNeedsElevation), findsOneWidget);
    expect(find.text(kProtectedBadge), findsNothing);
    expect(find.textContaining(kUncoveredProtected), findsNothing);
  });

  testWidgets('未提权：不谈身份 —— 不给「已对照 / 待人工核实」标记',
      (WidgetTester tester) async {
    // 未提权时读不到的原因就是没提权，一百多条无辜的服务进程都会被算成
    // 「名字对不上」。那时候贴身份标记是噪声，不是线索。
    await pumpTable(
      tester,
      finding: uncoveredProcess(
        elevationRequired: true,
        known: const KnownComponent(KnownKind.windows, 'Windows 系统组件'),
      ),
      elevated: false,
    );

    expect(find.text(kKnownWindowsBadge), findsNothing);
    expect(find.text(kKnownVendorBadge), findsNothing);
    expect(find.text(kUnidentifiedBadge), findsNothing);
    expect(find.textContaining(kKnownWindowsNote), findsNothing);
    expect(find.textContaining(kUnidentifiedNote), findsNothing);
  });
}
