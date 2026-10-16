// test/self_check_test.dart
//
// SelfCheck 判定矩阵。四条判定（permissionGaps / residualGaps /
// coverageComplete / coverageReached / enumerationDead）相互独立，
// 每一条都对应界面上的一个分支（app/lib/ui/selfcheck_panel.dart）。
//
// 这里要钉死的核心断言：**残留阻止「覆盖完整」，但不阻止「已达上限」；
// 枚举失败两条都挡。** 用户实测报过一次「蓝色覆盖完整 + 红色未覆盖同屏」，
// 修法的边界就写在这几个组合里。

import 'package:test/test.dart';
import 'package:yinhuguard_core/src/model/self_check.dart';

SelfCheck sc({
  bool elevated = false,
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

void main() {
  group('未提权', () {
    test('所有未解析条目都算权限缺口，绝不算残留', () {
      final SelfCheck check = sc(
        processUnresolvedPermission: 200,
        processUnresolvedOther: 43,
        servicesUnresolvedOther: 2,
      );
      expect(check.permissionGaps, 245);
      expect(check.residualGaps, 0);
      expect(check.hasPermissionGap, isTrue);
      expect(check.coverageComplete, isFalse);
      expect(check.coverageReached, isFalse);
      expect(check.enumerationDead, isFalse);
    });
  });

  group('已提权', () {
    test('残留不是权限缺口：覆盖完整为 false，但「已达上限」为 true', () {
      final SelfCheck check = sc(elevated: true, processUnresolvedOther: 2);
      expect(check.permissionGaps, 0);
      expect(check.residualGaps, 2);
      expect(check.coverageComplete, isFalse);
      expect(check.coverageReached, isTrue);
    });

    test('零缺口才算覆盖完整', () {
      final SelfCheck check = sc(elevated: true);
      expect(check.coverageComplete, isTrue);
      expect(check.coverageReached, isTrue);
    });
  });

  group('枚举失败', () {
    test('进程面为 0：既不算完整也不算达上限', () {
      final SelfCheck check = sc(elevated: true, processTotal: 0);
      expect(check.enumerationDead, isTrue);
      expect(check.coverageComplete, isFalse);
      expect(check.coverageReached, isFalse);
    });

    test('服务面为 0 同样报异常', () {
      expect(sc(elevated: true, servicesTotal: 0).enumerationDead, isTrue);
    });
  });
}
