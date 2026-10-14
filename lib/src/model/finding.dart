// lib/src/model/finding.dart
//
// 「发现」：一条观测 + 上层的判断结果。二期要往这里填 confidence /
// suggestedAction / changeRecord —— 三个字段一期恒为 null，但**必须存在**，
// 因为二期回滚要求「每条发现都能追溯到它导致的那次系统变更」，槽位现在不留，
// 二期就得做数据迁移。

import 'observation.dart';

class Finding {
  final Observation observation;

  /// 是否命中白名单。**只有 covered == true 的条目才可能为 true** ——
  /// 没查到的东西谈不上「确认是白的」，把它折进白名单等于二次掩盖。
  final bool allowlisted;

  // ---- 以下为一期占位，二期填充 ----
  final double? confidence;
  final String? suggestedAction;
  final String? changeRecord;

  Finding(
    this.observation, {
    required this.allowlisted,
    this.confidence,
    this.suggestedAction,
    this.changeRecord,
  });

  String get surface => observation.surface;
  String get locator => observation.locator;
  String get displayName => observation.displayName;
  String get criteria => observation.criteria;
  bool get attributesVerified => observation.attributesVerified;
  bool get hidden => observation.hidden;
  bool get system => observation.system;
  bool get elevationRequired => observation.elevationRequired;
  bool get covered => observation.covered;
  DateTime get timestamp => observation.timestamp;
}
