// lib/src/source/engine_observation_source.dart
//
// 真实引擎的观测来源。
//
// 每次扫描都在**独立 isolate** 里开 DLL、跑、关 DLL，把结果当普通 Dart 数据
// 传回来。理由是 C 侧句柄是裸指针，不能跨 isolate 送；而三个扫描各自要几千次
// 系统调用，在主 isolate 上跑会把界面冻住。每次重开 DLL 的代价是一次
// LoadLibrary，相对枚举本身可以忽略。
//
// 数据一律「先转成 Dart 值再释放 C 内存」：YhFindingList 持有 malloc 出来的
// 三块字符串，任何一条早期 return 漏了 free 就是真泄漏。

import 'dart:ffi';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import '../ffi/bindings.dart';
import '../model/observation.dart';
import '../model/self_check.dart';
import 'observation_source.dart';

/// 传给 isolate 的请求。只含可发送的字段（字符串）。
class _ScanRequest {
  final String dllPath;
  final String configPath;
  final String surface; // processes | run_keys | services | self_check

  const _ScanRequest(this.dllPath, this.configPath, this.surface);
}

/// 组装一条观测的 JSON 形态。返回 Map 而非 Observation，因为 isolate 之间
/// 只能送可发送对象 —— Map/List/String/num/bool 都可以。
Map<String, dynamic> _readFinding(Pointer<YhFinding> item) {
  final YhFinding f = item.ref;
  return <String, dynamic>{
    'surface': '',
    'locator': f.locator.toDartString(),
    'display_name': f.displayName.toDartString(),
    'criteria': f.criteria.toDartString(),
    'attributes_verified': f.attributesVerified != 0,
    'hidden': f.hidden != 0,
    'system': f.system != 0,
    'elevation_required': f.elevationRequired != 0,
    'covered': f.covered != 0,
    'timestamp': f.timestamp,
  };
}

/// isolate 入口：开引擎、跑一个扫描、全量转成 Dart 值、释放 C 内存。
List<Map<String, dynamic>> _scanInIsolate(_ScanRequest request) {
  final EngineBindings bindings = EngineBindings.open(request.dllPath);
  final Pointer<Utf8> configPath = request.configPath.toNativeUtf8();

  Pointer<Void> engine = nullptr;
  try {
    engine = bindings.engineCreate(configPath);
    if (engine == nullptr) {
      // 配置非法：把引擎给出的具体原因（含键名）原样抛出去。
      // code 用 kConfigInvalid —— 走到这里只可能是 load_config 拒绝。
      throw EngineException(kConfigInvalid, bindings.readLastError());
    }

    final Pointer<YhFindingList> list = calloc<YhFindingList>();
    try {
      final int code = switch (request.surface) {
        'processes' => bindings.scanProcesses(engine, list),
        'run_keys' => bindings.scanRunKeys(engine, list),
        'services' => bindings.scanServices(engine, list),
        _ => throw ArgumentError.value(request.surface, 'surface', '未知扫描面'),
      };
      if (code != kOk) {
        // 分配失败或参数无效。无论哪种都不能当成「没发现问题」。
        throw EngineException(code, bindings.readLastError());
      }

      final List<Map<String, dynamic>> out = <Map<String, dynamic>>[];
      for (int i = 0; i < list.ref.count; i++) {
        final Map<String, dynamic> row = _readFinding(list.ref.items + i);
        row['surface'] = request.surface;
        out.add(row);
      }
      return out;
    } finally {
      // 先释放 C 侧持有的字符串与数组，再释放结构本身。
      bindings.findingListFree(list);
      calloc.free(list);
    }
  } finally {
    if (engine != nullptr) {
      bindings.engineDestroy(engine);
    }
    calloc.free(configPath);
  }
}

/// isolate 入口：自检。
Map<String, dynamic> _selfCheckInIsolate(_ScanRequest request) {
  final EngineBindings bindings = EngineBindings.open(request.dllPath);
  final Pointer<Utf8> configPath = request.configPath.toNativeUtf8();

  Pointer<Void> engine = nullptr;
  try {
    engine = bindings.engineCreate(configPath);
    if (engine == nullptr) {
      throw EngineException(kConfigInvalid, bindings.readLastError());
    }
    final Pointer<YhSelfCheck> out = calloc<YhSelfCheck>();
    try {
      final int code = bindings.selfCheck(engine, out);
      if (code != kOk) {
        throw EngineException(code, bindings.readLastError());
      }
      final YhSelfCheck s = out.ref;
      return <String, dynamic>{
        'elevated': s.elevated != 0,
        'process_total': s.processTotal,
        'process_path_resolved': s.processPathResolved,
        'session0_visible': s.session0Visible,
        'services_total': s.servicesTotal,
        'services_with_path': s.servicesWithPath,
        // 「没查到」的两类原因必须一起带回来，界面才能分红/灰。
        // 少一个就退回到「一律报红」，也就是这个模型要避免的老问题。
        'process_unresolved_permission': s.processUnresolvedPermission,
        'process_unresolved_other': s.processUnresolvedOther,
        'services_unresolved_permission': s.servicesUnresolvedPermission,
        'services_unresolved_other': s.servicesUnresolvedOther,
      };
    } finally {
      calloc.free(out);
    }
  } finally {
    if (engine != nullptr) {
      bindings.engineDestroy(engine);
    }
    calloc.free(configPath);
  }
}

class EngineObservationSource implements ObservationSource {
  final String dllPath;
  final String configPath;

  EngineObservationSource({required this.dllPath, required this.configPath});

  Future<List<Observation>> _scan(String surface) async {
    final List<Map<String, dynamic>> rows =
        await Isolate.run(() => _scanInIsolate(_ScanRequest(dllPath, configPath, surface)));
    return <Observation>[
      for (final Map<String, dynamic> row in rows) Observation.fromJson(row),
    ];
  }

  @override
  Future<List<Observation>> scanProcesses() => _scan('processes');

  @override
  Future<List<Observation>> scanRunKeys() => _scan('run_keys');

  @override
  Future<List<Observation>> scanServices() => _scan('services');

  @override
  Future<SelfCheck> selfCheck() async {
    final Map<String, dynamic> json = await Isolate.run(
      () => _selfCheckInIsolate(_ScanRequest(dllPath, configPath, 'self_check')),
    );
    return SelfCheck.fromJson(json);
  }
}
