// lib/src/source/observation_source.dart
//
// 观测来源的抽象。存在的理由：真实 Win32 与合成 fixture 必须能被同一套
// 编排、判据、报告代码消费。没有这层抽象，fixture 验证就只能测一半逻辑，
// 而「不碰用户机器」的前提（spec §11.2）会让另一半永远没被测过。
//
// 刻意做成异步：三个扫描各自要几千次系统调用，同步跑会把界面卡死。

import '../model/observation.dart';
import '../model/self_check.dart';

/// 引擎返回了非 0 返回码。配置非法（code 1）时 [message] 里是引擎给出的
/// 具体原因，包含不合法的键名 —— spec §2 硬约束 3 要求指名键名，靠它传达。
class EngineException implements Exception {
  final int code;
  final String message;

  EngineException(this.code, this.message);

  @override
  String toString() => 'EngineException($code): $message';
}

/// 一次扫描能拿到的全部内容。
abstract interface class ObservationSource {
  Future<SelfCheck> selfCheck();
  Future<List<Observation>> scanProcesses();
  Future<List<Observation>> scanRunKeys();
  Future<List<Observation>> scanServices();
}
