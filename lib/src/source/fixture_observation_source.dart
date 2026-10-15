// lib/src/source/fixture_observation_source.dart
//
// 合成 fixture 的观测来源。存在的唯一理由是 spec §11.2：**不碰用户机器**。
// 没有它，整个上层（编排、判据、报告、界面）就只能在真机上才能跑，
// 而那件事被明确禁止。
//
// 故意不做的事：
//   * 缺某个 surface 时返回空列表而不是抛异常 —— fixture 只需要包含它想测的面
//   * 不做任何校验/规范化 —— 它必须能造出「坏数据」，否则测不出坏数据被正确处理
//
// snake_case -> camelCase 的映射在 Observation/SelfCheck.fromJson 里显式写出，
// 这里只负责按 surface 分发，不碰字段名。

import '../model/observation.dart';
import '../model/self_check.dart';
import 'observation_source.dart';

/// 覆盖全部七个扫描面（含二期深度扫描）。fixture 里没有的面返回空列表。
class FixtureObservationSource implements ObservationSource {
  final Map<String, dynamic> _json;

  FixtureObservationSource.fromJson(this._json);

  List<Observation> _forSurface(String surface) {
    final Object? raw = _json['observations'];
    if (raw is! List) {
      return <Observation>[];
    }
    return <Observation>[
      for (final Object? item in raw)
        if (item is Map<String, dynamic> && item['surface'] == surface)
          Observation.fromJson(item),
    ];
  }

  SelfCheck get selfCheckValue {
    final Object? raw = _json['self_check'];
    if (raw is! Map<String, dynamic>) {
      // 没有 self_check 的 fixture 也不能被当成「一切正常」：给出一个明确的
      // 零值，且 elevated=false + session0Visible=0 会触发界面上的未覆盖提示。
      return SelfCheck(
        elevated: false,
        processTotal: 0,
        processPathResolved: 0,
        session0Visible: 0,
        servicesTotal: 0,
        servicesWithPath: 0,
      );
    }
    return SelfCheck.fromJson(raw);
  }

  @override
  Future<List<Observation>> scanProcesses() async => _forSurface('processes');

  @override
  Future<List<Observation>> scanRunKeys() async => _forSurface('run_keys');

  @override
  Future<List<Observation>> scanServices() async => _forSurface('services');

  // ---- 二期深度扫描 ----
  @override
  Future<List<Observation>> scanRegistryPayloads() async =>
      _forSurface('registry_payloads');

  @override
  Future<List<Observation>> scanDrivers() async => _forSurface('drivers');

  @override
  Future<List<Observation>> scanFileDrops() async => _forSurface('file_drops');

  @override
  Future<List<Observation>> scanScheduledTasks() async =>
      _forSurface('scheduled_tasks');

  @override
  Future<SelfCheck> selfCheck() async => selfCheckValue;
}
