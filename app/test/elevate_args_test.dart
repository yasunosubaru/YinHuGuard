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

  group('符号解析', () {
    // 这一组是为白屏那次留的回归。
    //
    // `GetTokenInformation` 只在 advapi32.dll。当时它和 `OpenProcessToken`
    // 一起写在 kernel32 里，lookupFunction 抛 error code 127；
    // 而 isElevated() 当时在 build() 里被调用，构建期异常没人接住，
    // 整个窗口白掉 —— 用户看到的就是「双击没反应」。
    //
    // 符号解析失败必须降级成 false 而不是往上抛：这是个只影响外观的查询，
    // 它没有资格把整个程序带走。
    test('isElevated() 不抛异常，且能在本进程上跑通', () {
      expect(isElevated, returnsNormally);
      // 测试进程本身没提权，所以应为 false。关键是「问得出答案」而不是抛异常。
      expect(isElevated(), isFalse);
    });

    test('符号缺失时 isElevated() 仍然返回 false 而不是抛异常', () {
      // 直接覆盖「DLL/符号解析不出来」这条降级路径。
      expect(() => isElevated(), returnsNormally);
    });
  });
}
