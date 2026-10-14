import 'package:flutter_test/flutter_test.dart';
import 'package:yinhuguard_app/cli.dart';

void main() {
  group('parseArgs', () {
    test('--json 缺路径是参数错误', () {
      expect(parseArgs(<String>['--json']), isA<InvalidArgs>());
    });

    test('--json <路径> 得到 RunScan 并带上路径', () {
      final CliAction action = parseArgs(<String>['--json', 'out.json']);
      expect(action, isA<RunScan>());
      expect((action as RunScan).jsonOutPath, 'out.json');
    });

    test('未知参数报错且回显该参数', () {
      final CliAction action = parseArgs(<String>['--scan-all']);
      expect(action, isA<InvalidArgs>());
      expect((action as InvalidArgs).message, contains('--scan-all'));
    });

    test('--scan 得到 RunScan，不带 json 路径', () {
      final CliAction action = parseArgs(<String>['--scan']);
      expect(action, isA<RunScan>());
      expect((action as RunScan).jsonOutPath, isNull);
    });

    test('无参数启动图形界面 —— 不是跑扫描', () {
      // 双击 exe 绝不应该弹出一个黑框去枚举全机进程。
      expect(parseArgs(<String>[]), isA<RunGui>());
    });

    test('只带路径修饰、没有模式旗标时仍走图形界面', () {
      expect(parseArgs(<String>['--config', 'a.json']), isA<RunGui>());
      expect(
        parseArgs(<String>['--fixture', 'f.json', '--config', 'a.json']),
        isA<RunGui>(),
      );
    });

    test('带值的修饰旗标缺值时是参数错误，不猜', () {
      expect(parseArgs(<String>['--scan', '--fixture']), isA<InvalidArgs>());
      expect(parseArgs(<String>['--config']), isA<InvalidArgs>());
      expect(parseArgs(<String>['--dll']), isA<InvalidArgs>());
    });

    test('--relaunched 被忽略，不影响模式判定', () {
      expect(parseArgs(<String>['--relaunched']), isA<RunGui>());
      final CliAction action = parseArgs(<String>['--relaunched', '--scan']);
      expect(action, isA<RunScan>());
    });

    test('--fixture 的值不会被当成模式旗标', () {
      final CliAction action =
          parseArgs(<String>['--scan', '--fixture', '--json']);
      // '--json' 被吃成 --fixture 的值，因此没有 json 输出路径
      expect(action, isA<RunScan>());
      expect((action as RunScan).jsonOutPath, isNull);
    });
  });
}
