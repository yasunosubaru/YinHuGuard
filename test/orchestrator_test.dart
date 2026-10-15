import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:yinhuguard_core/src/model/finding.dart';
import 'package:yinhuguard_core/src/model/observation.dart';
import 'package:yinhuguard_core/src/model/self_check.dart';
import 'package:yinhuguard_core/src/scan/orchestrator.dart';
import 'package:yinhuguard_core/src/source/fixture_observation_source.dart';
import 'package:yinhuguard_core/src/source/observation_source.dart';

FixtureObservationSource loadFixture(String name) {
  final String text = File('fixtures/$name').readAsStringSync();
  return FixtureObservationSource.fromJson(jsonDecode(text) as Map<String, dynamic>);
}

/// 一个能按剧本抛异常/返回数据的来源，用来测编排的失败语义。
class _ScriptedSource implements ObservationSource {
  final bool throwOnServices;
  _ScriptedSource({this.throwOnServices = false});

  @override
  Future<List<Observation>> scanProcesses() async => <Observation>[];

  @override
  Future<List<Observation>> scanRunKeys() async => <Observation>[];

  @override
  Future<List<Observation>> scanServices() async {
    if (throwOnServices) {
      throw EngineException(2, '分配失败');
    }
    return <Observation>[];
  }

  @override
  Future<SelfCheck> selfCheck() async => SelfCheck(
        elevated: false,
        processTotal: 0,
        processPathResolved: 0,
        session0Visible: 0,
        servicesTotal: 0,
        servicesWithPath: 0,
      );
}

void main() {
  group('进度回调', () {
    test('按 processes -> run_keys -> services 顺序回调，计数从 1 开始', () async {
      final Orchestrator orchestrator = Orchestrator(loadFixture('clean_machine.json'));
      final List<String> calls = <String>[];
      await orchestrator.scan((String surface, int index, int total) {
        calls.add('$surface:$index/$total');
      });
      expect(calls, <String>[
        'processes:1/3',
        'run_keys:2/3',
        'services:3/3',
      ]);
    });

    test('kScanOrder 与 spec 的三段一致', () {
      expect(kScanOrder, <String>['processes', 'run_keys', 'services']);
    });
  });

  group('未覆盖语义 —— Review Focus #1', () {
    test('干净机器的 findings 不是空的，未覆盖条数大于零', () async {
      final Orchestrator orchestrator = Orchestrator(loadFixture('clean_machine.json'));
      await orchestrator.scan((_, __, ___) {});

      // 这是本项目最重要的一条断言：没有命中 ≠ 没有发现。
      expect(orchestrator.result.findings, isNotEmpty);
      expect(orchestrator.uncoveredCount, greaterThan(0));
      expect(orchestrator.result.findings.any((Finding f) => !f.covered), isTrue);
    });

    test('未提权时 selfCheck 的三个计数如实报告', () async {
      final Orchestrator orchestrator = Orchestrator(loadFixture('clean_machine.json'));
      await orchestrator.scan((_, __, ___) {});

      expect(orchestrator.result.selfCheck.elevated, isFalse);
      expect(orchestrator.result.selfCheck.session0Visible, 0);
      expect(orchestrator.result.selfCheck.processTotal, 690);
      expect(orchestrator.result.selfCheck.processPathResolved, 434);
      expect(orchestrator.result.selfCheck.servicesTotal, 360);
      expect(orchestrator.result.selfCheck.servicesWithPath, 358);
      // 非提权直接判不完整：Session 0 是权限拦住的，不需要等计数来证明。
      expect(
        orchestrator.result.selfCheck.coverageIncomplete(orchestrator.uncoveredCount),
        isTrue,
      );
      expect(orchestrator.result.selfCheck.coverageComplete, isFalse);
      // 有进程拿到了 PID 却拿不到路径 —— 这就是「本来该看、没看到」的证据。
      expect(orchestrator.result.selfCheck.hasUnresolvedProcesses, isTrue);
    });

    test('提权且各面计数健康时才敢说覆盖完整', () async {
      // 这一条防的是「提权了但枚举整个失败返回 0 个」冒充完整的情况。
      final SelfCheck broken = SelfCheck(
        elevated: true,
        processTotal: 0,
        processPathResolved: 0,
        session0Visible: 0,
        servicesTotal: 0,
        servicesWithPath: 0,
      );
      expect(broken.coverageComplete, isFalse,
          reason: '枚举返回 0 个不能算覆盖完整，那是「什么都没枚举到」');
      // 而且这种情形下 hasUnresolvedProcesses 是 false（0 不小于 0），
      // 所以完整性判断必须另加计数 > 0 的条件，光看「有没有未解析项」会漏。
      expect(broken.hasUnresolvedProcesses, isFalse);

      final SelfCheck healthy = SelfCheck(
        elevated: true,
        processTotal: 690,
        processPathResolved: 690,
        session0Visible: 220,
        servicesTotal: 360,
        servicesWithPath: 360,
      );
      expect(healthy.coverageComplete, isTrue);
      expect(healthy.coverageIncomplete(0), isFalse);
    });

    test('发现级未覆盖也会让结论判为不完整', () {
      // 自检计数健康但有一条具体项没读出来：只有发现级的数字能看出来。
      final SelfCheck healthy = SelfCheck(
        elevated: true,
        processTotal: 10,
        processPathResolved: 10,
        session0Visible: 5,
        servicesTotal: 10,
        servicesWithPath: 10,
      );
      expect(healthy.coverageIncomplete(0), isFalse);
      expect(healthy.coverageIncomplete(1), isTrue);
    });

    test('三个扫描面的发现都被收集，中文与空格的 locator 原样返回', () async {
      final Orchestrator orchestrator = Orchestrator(loadFixture('silverfox_sample.json'));
      await orchestrator.scan((_, __, ___) {});

      final Set<String> surfaces =
          orchestrator.result.findings.map((Finding f) => f.surface).toSet();
      expect(surfaces, containsAll(<String>['processes', 'run_keys', 'services']));

      // 中文路径错一个字符，报告里就是乱码，而「乱码文件名」正是银狐的民间判据 ——
      // 编码错了会直接伪造出一个命中，所以这里逐字比对。
      const String chinese = r'C:\Windows\Temp\临时 目录\隐藏 文件.exe';
      expect(
        orchestrator.result.findings.any((Finding f) => f.locator == chinese),
        isTrue,
        reason: '中文+空格路径必须逐字节原样保留',
      );
    });
  });

  group('白名单折叠', () {
    test('visibleFindings 与 allowlistedFindings 相加等于 findings', () async {
      final Orchestrator orchestrator = Orchestrator(
        loadFixture('silverfox_sample.json'),
        userAllowlist: <String>['QduoQFO.exe'],
      );
      await orchestrator.scan((_, __, ___) {});

      expect(
        orchestrator.visibleFindings.length + orchestrator.allowlistedFindings.length,
        orchestrator.result.findings.length,
      );
      expect(orchestrator.allowlistedFindings, hasLength(1));
      // 折叠掉的条目仍保留在结果里 —— 用户要能回头看自己白掉了什么。
      expect(
        orchestrator.result.findings.any((Finding f) => f.allowlisted),
        isTrue,
      );
    });
  });

  group('失败语义', () {
    test('某个扫描面抛异常时整体重抛', () async {
      final Orchestrator orchestrator =
          Orchestrator(_ScriptedSource(throwOnServices: true));
      await expectLater(
        orchestrator.scan((_, __, ___) {}),
        throwsA(isA<EngineException>()),
      );
    });

    test('失败后没有结果可读 —— 不返回半份结果', () async {
      final Orchestrator orchestrator =
          Orchestrator(_ScriptedSource(throwOnServices: true));
      try {
        await orchestrator.scan((_, __, ___) {});
      } on EngineException {
        // 预期
      }
      expect(() => orchestrator.result, throwsA(isA<StateError>()));
    });
  });
}
