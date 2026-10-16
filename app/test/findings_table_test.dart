// app/test/findings_table_test.dart
//
// 行级措辞的回归：已提权时不允许再出现「需要提权」/「以管理员身份重跑」。
// 用户的第一条反馈就是「我已经给了最高权限，为什么还写着要提权」——
// 那句话在提权后的扫描里必须换成「系统保护」。

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yinhuguard_app/strings.dart';
import 'package:yinhuguard_app/ui/findings_table.dart';
import 'package:yinhuguard_core/yinhuguard_core.dart';

Finding uncoveredProcess({required bool elevationRequired}) => Finding(
      Observation(
        surface: 'processes',
        locator: 'csrss.exe',
        displayName: 'csrss.exe',
        criteria: 'file_attr_hs',
        attributesVerified: false,
        hidden: false,
        system: false,
        elevationRequired: elevationRequired,
        covered: false,
        timestamp: DateTime.utc(2026, 1, 1),
      ),
      allowlisted: false,
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
  testWidgets('已提权：受保护条目写「系统保护」，不再要求提权',
      (WidgetTester tester) async {
    await pumpTable(
      tester,
      finding: uncoveredProcess(elevationRequired: true),
      elevated: true,
    );

    expect(find.text(kProtectedBadge), findsOneWidget);
    expect(find.text(kUncoveredBadge), findsOneWidget);
    expect(find.text(kUncoveredProtected), findsOneWidget);
    expect(find.text(kNeedsElevationBadge), findsNothing);
    expect(find.text(kUncoveredNeedsElevation), findsNothing);
  });

  testWidgets('未提权：仍然写「需要提权」并给出重跑指引',
      (WidgetTester tester) async {
    await pumpTable(
      tester,
      finding: uncoveredProcess(elevationRequired: true),
      elevated: false,
    );

    expect(find.text(kNeedsElevationBadge), findsOneWidget);
    expect(find.text(kUncoveredNeedsElevation), findsOneWidget);
    expect(find.text(kProtectedBadge), findsNothing);
    expect(find.text(kUncoveredProtected), findsNothing);
  });
}
