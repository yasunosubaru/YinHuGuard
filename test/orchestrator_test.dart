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
  Future<List<Observation>> scanRegistryPayloads() async => <Observation>[];

  @override
  Future<List<Observation>> scanDrivers() async => <Observation>[];

  @override
  Future<List<Observation>> scanFileDrops() async => <Observation>[];

  @override
  Future<List<Observation>> scanScheduledTasks() async => <Observation>[];

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
    test('按固定顺序回调七个面，计数从 1 开始', () async {
      final Orchestrator orchestrator = Orchestrator(loadFixture('clean_machine.json'));
      final List<String> calls = <String>[];
      await orchestrator.scan((String surface, int index, int total) {
        calls.add('$surface:$index/$total');
      });
      // 顺序按「耗时从小到大」排：注册表飞快，计划任务最慢。
      // 界面上先看到结果、慢的排后面，进度条才不会像卡住。
      expect(calls, <String>[
        'processes:1/7',
        'run_keys:2/7',
        'services:3/7',
        'registry_payloads:4/7',
        'drivers:5/7',
        'file_drops:6/7',
        'scheduled_tasks:7/7',
      ]);
    });

    test('kScanOrder 覆盖一期三段与二期四个深扫面', () {
      expect(kScanOrder, <String>[
        'processes',
        'run_keys',
        'services',
        'registry_payloads',
        'drivers',
        'file_drops',
        'scheduled_tasks',
      ]);
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
      expect(orchestrator.result.selfCheck.coverageComplete, isFalse);
      // 未提权 → 权限缺口必然存在 → 该显示红色警告。
      expect(orchestrator.result.selfCheck.hasPermissionGap, isTrue);
    });

    test('权限缺口与扫描期残留被分成两类', () {
      // 这是「完整扫描」能成立的前提：两类混在一起时，警告永远关不掉。
      final SelfCheck allPermission = SelfCheck(
        elevated: false,
        processTotal: 690,
        processPathResolved: 434,
        session0Visible: 0,
        servicesTotal: 360,
        servicesWithPath: 358,
        processUnresolvedPermission: 256,
        processUnresolvedOther: 0,
        servicesUnresolvedPermission: 2,
        servicesUnresolvedOther: 0,
      );
      expect(allPermission.permissionGaps, 258);
      expect(allPermission.residualGaps, 0);
      expect(allPermission.hasPermissionGap, isTrue);
      expect(allPermission.hasResidual, isFalse);
      expect(allPermission.coverageComplete, isFalse);
    });

    test('提权后有保护进程残留 => 不报红但也不算完整，显示灰色残留提示', () {
      // 这是本次真 bug 的回归：`!elevated || permissionGaps > 0` 让已提权机器
      // 也永远报红，因为杀软保护进程（MsMpEng 等）连管理员都不放行 OpenProcess。
      // 修复后：权限缺口归零，但残留存在 -> 不报红，显示灰色残留提示，且 coverageComplete 为 false。
      final SelfCheck elevated = SelfCheck(
        elevated: true,
        processTotal: 690,
        processPathResolved: 680,
        session0Visible: 220,
        servicesTotal: 360,
        servicesWithPath: 360,
        processUnresolvedPermission: 10,  // 保护进程，提权也读不到
        processUnresolvedOther: 0,
        servicesUnresolvedPermission: 0,
        servicesUnresolvedOther: 0,
      );
      expect(elevated.permissionGaps, 0,
          reason: '已提权时未解析项归残留，权限缺口恒为 0');
      expect(elevated.hasPermissionGap, isFalse,
          reason: '已提权时未解析的是保护进程残留，不是权限缺口，不该报红');
      expect(elevated.hasResidual, isTrue,
          reason: '残留存在，界面该灰字提一句');
      // **核心断言**：有保护进程残留时，coverageComplete 为 false（不完整），但不报红。
      expect(elevated.coverageComplete, isFalse,
          reason: '残留虽正常但仍属未覆盖，完整性要求零未覆盖');
    });

    test('提权了但枚举整个失败返回 0 个，不能冒充覆盖完整', () {
      // 光看 permissionGaps 会漏：0 不大于 0，所以必须另加计数 > 0 的条件。
      final SelfCheck broken = SelfCheck(
        elevated: true,
        processTotal: 0,
        processPathResolved: 0,
        session0Visible: 0,
        servicesTotal: 0,
        servicesWithPath: 0,
        processUnresolvedPermission: 0,
        processUnresolvedOther: 0,
        servicesUnresolvedPermission: 0,
        servicesUnresolvedOther: 0,
      );
      expect(broken.coverageComplete, isFalse,
          reason: '枚举返回 0 个是「什么都没枚举到」，不是「全部检查过且干净」');
    });

    test('已提权时未解析项归残留，不报红但也不算完整', () {
      final SelfCheck partlyBlocked = SelfCheck(
        elevated: true,
        processTotal: 690,
        processPathResolved: 600,
        session0Visible: 150,
        servicesTotal: 360,
        servicesWithPath: 360,
        processUnresolvedPermission: 90,
        processUnresolvedOther: 0,
        servicesUnresolvedPermission: 0,
        servicesUnresolvedOther: 0,
      );
      expect(partlyBlocked.hasPermissionGap, isFalse,
          reason: '已提权 => 未解析是保护进程残留，不是权限缺口');
      expect(partlyBlocked.coverageComplete, isFalse,
          reason: '残留虽正常但仍属未覆盖，完整性要求零未覆盖');
    });

    test('未提权时即便引擎把缺口都算成了 residual，也仍然报权限缺口', () {
      // 保险：完整性判断不该完全依赖引擎是否把 ACCESS_DENIED 逐条算清楚。
      final SelfCheck mislabelled = SelfCheck(
        elevated: false,
        processTotal: 690,
        processPathResolved: 434,
        session0Visible: 0,
        servicesTotal: 360,
        servicesWithPath: 358,
        processUnresolvedPermission: 0,
        processUnresolvedOther: 256,
      );
      expect(mislabelled.hasPermissionGap, isTrue,
          reason: '非提权时 Session 0 必然有一整块看不到，不能因为分类被算错就放过');
      expect(mislabelled.coverageComplete, isFalse);
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
