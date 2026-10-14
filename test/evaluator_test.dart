import 'package:test/test.dart';
import 'package:yinhuguard_core/src/criteria/evaluator.dart';
import 'package:yinhuguard_core/src/model/finding.dart';
import 'package:yinhuguard_core/src/model/observation.dart';

Observation obs({
  String surface = 'processes',
  String locator = r'C:\a\b.exe',
  String displayName = 'b.exe',
  String criteria = 'file_attr_hs',
  bool attributesVerified = true,
  bool hidden = true,
  bool system = false,
  bool elevationRequired = false,
  bool covered = true,
}) {
  return Observation(
    surface: surface,
    locator: locator,
    displayName: displayName,
    criteria: criteria,
    attributesVerified: attributesVerified,
    hidden: hidden,
    system: system,
    elevationRequired: elevationRequired,
    covered: covered,
    timestamp: DateTime.utc(2026, 10, 14),
  );
}

void main() {
  group('取值集合', () {
    test('surface 只接受 spec 规定的三值', () {
      expect(kSurfaces, <String>['processes', 'run_keys', 'services']);
    });

    test('criteria 只接受 spec 规定的三值', () {
      expect(kCriteria, <String>[
        'file_attr_hs',
        'service_interpreter',
        'service_path_heuristic',
      ]);
    });

    test('未知 surface 抛异常而不是静默接受', () {
      // release 构建会把 assert 编译掉，所以这里必须是真异常。
      expect(
        () => obs(surface: 'drivers'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('未知 criteria 抛异常而不是静默接受', () {
      expect(
        () => obs(criteria: 'name_match'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('未覆盖语义', () {
    test('covered=false 的观测原样保留，不被白名单折叠，也不被丢弃', () {
      final List<Finding> out = evaluate(
        <Observation>[obs(covered: false)],
        userAllowlist: <String>['b.exe'],
      );
      expect(out, hasLength(1));
      expect(out.single.covered, isFalse);
      // 没查到的东西谈不上「确认是白的」
      expect(out.single.allowlisted, isFalse);
    });

    test('uncoveredCount 数得出来', () {
      final List<Finding> out = evaluate(
        <Observation>[
          obs(covered: true),
          obs(locator: r'C:\c\d.exe', displayName: 'd.exe', covered: false),
          obs(locator: r'C:\e\f.exe', displayName: 'f.exe', covered: false),
        ],
        userAllowlist: const <String>[],
      );
      expect(uncoveredCount(out), 2);
    });

    test('全未覆盖时 findings 不是空列表 —— 空列表正是「干净」的假象来源', () {
      final List<Finding> out = evaluate(
        <Observation>[obs(covered: false), obs(covered: false)],
        userAllowlist: const <String>[],
      );
      expect(out, isNotEmpty);
    });
  });

  group('白名单折叠', () {
    test('命中用户白名单时 allowlisted=true 且条目仍在', () {
      final List<Finding> out = evaluate(
        <Observation>[obs()],
        userAllowlist: <String>['b.exe'],
      );
      expect(out.single.allowlisted, isTrue);
      expect(out.single.locator, r'C:\a\b.exe');
    });

    test('白名单按文件名匹配，不按完整路径', () {
      final List<Finding> out = evaluate(
        <Observation>[obs(locator: r'C:\Users\me\AppData\Local\b.exe')],
        userAllowlist: <String>['b.exe'],
      );
      expect(out.single.allowlisted, isTrue);
    });

    test('大小写不敏感', () {
      final List<Finding> out = evaluate(
        <Observation>[obs(locator: r'C:\a\B.EXE')],
        userAllowlist: <String>['b.exe'],
      );
      expect(out.single.allowlisted, isTrue);
    });

    test('未命中白名单时为 false', () {
      final List<Finding> out = evaluate(
        <Observation>[obs()],
        userAllowlist: <String>['explorer.exe'],
      );
      expect(out.single.allowlisted, isFalse);
    });

    test('正斜杠路径也取得出文件名', () {
      expect(basenameOf('C:/a/b/c.exe'), 'c.exe');
      expect(basenameOf(r'C:\a\b\c.exe'), 'c.exe');
      expect(basenameOf('c.exe'), 'c.exe');
    });
  });

  group('二期占位字段', () {
    test('confidence / suggestedAction / changeRecord 一期恒为 null', () {
      final List<Finding> out = evaluate(
        <Observation>[obs()],
        userAllowlist: const <String>[],
      );
      expect(out.single.confidence, isNull);
      expect(out.single.suggestedAction, isNull);
      expect(out.single.changeRecord, isNull);
    });
  });

  group('保序', () {
    test('evaluate 不重排、不去重', () {
      final List<Observation> input = <Observation>[
        obs(locator: r'C:\z\z.exe'),
        obs(locator: r'C:\a\a.exe'),
        obs(locator: r'C:\z\z.exe'),
      ];
      final List<Finding> out = evaluate(input, userAllowlist: const <String>[]);
      expect(
        out.map((Finding f) => f.locator).toList(),
        <String>[r'C:\z\z.exe', r'C:\a\a.exe', r'C:\z\z.exe'],
      );
    });
  });
}
