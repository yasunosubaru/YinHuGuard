import 'dart:ffi';

import 'package:flutter_test/flutter_test.dart';
import 'package:yinhuguard_app/elevate.dart';

// 提权路径在本机**不会被真实执行**（一执行就弹 UAC，且用户的约束是
// 不在这台机器上跑任何东西）。所以能测的两件事就是：
//   1) 参数拼装正确
//   2) SHELLEXECUTEINFOW 的结构体尺寸正确
// 第 2 条尤其重要：字段偏移错一个，调用就落在别的字段上，而 Windows 只会
// 返回一个泛泛的失败码，看起来像「提权被拒绝」。

void main() {
  group('buildRelaunchArgs', () {
    test('保留 --fixture 及其路径', () {
      final List<String> out = buildRelaunchArgs(
        <String>['--scan', '--fixture', r'..\fixtures\clean_machine.json'],
      );
      expect(out, contains('--fixture'));
      expect(out, contains(r'..\fixtures\clean_machine.json'));
    });

    test('fp 不带 --fixture 时不凭空造出路径', () {
      final List<String> out = buildRelaunchArgs(<String>['--scan']);
      expect(out, isNot(contains('--fixture')));
    });

    test('保留 --config 与 --dll 的值', () {
      final List<String> out = buildRelaunchArgs(
        <String>['--config', r'C:\a\rules.json', '--dll', r'C:\a\e.dll'],
      );
      expect(out, contains(r'C:\a\rules.json'));
      expect(out, contains(r'C:\a\e.dll'));
    });

    test('不重复累积 --relaunched', () {
      final List<String> once = buildRelaunchArgs(<String>['--scan']);
      final List<String> twice = buildRelaunchArgs(once);
      expect(twice.where((String a) => a == '--relaunched').length, 1);
    });

    test('已经带过 --relaunched 时被识别出来', () {
      expect(alreadyRelaunched(<String>['--relaunched']), isTrue);
      expect(alreadyRelaunched(<String>['--scan']), isFalse);
    });

    test('--fixture 缺值时不吞掉下一个旗标', () {
      final List<String> out = buildRelaunchArgs(<String>['--fixture']);
      expect(out, contains('--fixture'));
      expect(out, contains('--relaunched'));
    });
  });

  group('SHELLEXECUTEINFOW 布局（x64）', () {
    test('尺寸是 112 字节', () {
      // cbSize 4 / fMask 4 / 6 个指针或句柄 / nShow 4(补齐到 56) /
      // hInstApp / lpIDList / lpClass / hkeyClass / dwHotKey 4(补齐到 96) /
      // hIcon|hMonitor / hProcess
      expect(sizeOf<ShellExecuteInfo>(), 112);
    });
  });
}
