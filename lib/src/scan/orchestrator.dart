// lib/src/scan/orchestrator.dart
//
// 扫描编排：按固定顺序跑全部扫描面，把观测过一遍判据，攒成一份 ScanResult。
//
// 前三个面固定为 processes -> run_keys -> services，与上游 bat 的
// 「扫描1/3、2/3、3/3」一致，也让界面上的进度语义和用户的心理模型对上；
// 其余四个是二期深扫面，按耗时递增排在后面。
//
// 任一扫描面抛异常时整体重抛、不返回半份结果：半份结果的危险在于它看起来
// 像一份完整报告，读者无从知道少了哪一面。

import '../criteria/evaluator.dart';
import '../model/finding.dart';
import '../model/observation.dart';
import '../model/self_check.dart';
import '../source/observation_source.dart';
import '../triage/known_components.dart';

/// 扫描面的固定顺序。
const List<String> kScanOrder = <String>[
  'processes',
  'run_keys',
  'services',
  // ---- 二期深度扫描 ----
  // 顺序按「耗时从小到大」排：注册表飞快，计划任务最慢。
  // 界面上先看到结果再出慢的那几个面，进度条才不会像是卡住了。
  'registry_payloads',
  'drivers',
  'file_drops',
  'scheduled_tasks',
];

class ScanResult {
  final SelfCheck selfCheck;
  final List<Finding> findings;
  final DateTime startedAt;
  final DateTime finishedAt;

  ScanResult({
    required this.selfCheck,
    required this.findings,
    required this.startedAt,
    required this.finishedAt,
  });

  Duration get duration => finishedAt.difference(startedAt);
}

class Orchestrator {
  final ObservationSource source;

  /// 用户白名单（rules.json 的 process_allowlist 与用户后来加的合并后传进来）。
  final List<String> userAllowlist;

  /// 未覆盖条目的自动对照清单（rules.json 的 known_components 段）。
  /// 只做名字层面的分诊，见 triage/known_components.dart。
  final KnownComponents knownComponents;

  ScanResult? _result;

  Orchestrator(
    this.source, {
    this.userAllowlist = const <String>[],
    this.knownComponents = const KnownComponents(),
  });

  ScanResult get result {
    final ScanResult? snapshot = _result;
    if (snapshot == null) {
      throw StateError('scan() 尚未成功完成，没有结果可读');
    }
    return snapshot;
  }

  /// 跑一遍全部扫描面。[onProgress] 在**每个面开始前**回调一次，
  /// 参数为 (面名, 第几个, 共几个)，从 1 开始计数。
  Future<void> scan(
    void Function(String surface, int index, int total) onProgress,
  ) async {
    final DateTime startedAt = DateTime.now().toUtc();

    // 自检放最前：它便宜，且它的结果决定界面要不要显示未覆盖提示，
    // 用户越早看到「这次没看到什么」越好。
    final SelfCheck selfCheck = await source.selfCheck();

    final List<Observation> observations = <Observation>[];
    for (int i = 0; i < kScanOrder.length; i++) {
      final String surface = kScanOrder[i];
      onProgress(surface, i + 1, kScanOrder.length);
      final List<Observation> batch = switch (surface) {
        'processes' => await source.scanProcesses(),
        'run_keys' => await source.scanRunKeys(),
        'services' => await source.scanServices(),
        'registry_payloads' => await source.scanRegistryPayloads(),
        'drivers' => await source.scanDrivers(),
        'file_drops' => await source.scanFileDrops(),
        'scheduled_tasks' => await source.scanScheduledTasks(),
        _ => throw StateError('kScanOrder 里出现了未处理的扫描面: $surface'),
      };
      observations.addAll(batch);
    }

    _result = ScanResult(
      selfCheck: selfCheck,
      findings: evaluate(
        observations,
        userAllowlist: userAllowlist,
        knownComponents: knownComponents,
      ),
      startedAt: startedAt,
      finishedAt: DateTime.now().toUtc(),
    );
  }

  /// 未折叠进白名单的发现 —— 界面默认视图。
  List<Finding> get visibleFindings =>
      result.findings.where((Finding f) => !f.allowlisted).toList();

  /// 被白名单折叠的发现。**保留而不是删除**：用户要能回头看自己白掉了什么。
  List<Finding> get allowlistedFindings =>
      result.findings.where((Finding f) => f.allowlisted).toList();

  /// 因权限或环境原因未检查的条目数。
  int get uncoveredCount => uncoveredCountOf(result.findings);
}
