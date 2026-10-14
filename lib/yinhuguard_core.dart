// lib/yinhuguard_core.dart
//
// 判据层的公开接口。app 包只从这里 import —— 直接深入 lib/src/ 会让
// 「哪些是稳定接口、哪些是内部实现」失去边界，重构时无从判断谁在依赖什么。
//
// 刻意不导出 src/ffi/bindings.dart：C ABI 的结构体布局是引擎与绑定层之间的
// 私事，app 不该也不需要看见它。

library yinhuguard_core;

export 'src/criteria/evaluator.dart';
export 'src/criteria/redact.dart';
export 'src/model/finding.dart';
export 'src/model/observation.dart';
export 'src/model/self_check.dart';
export 'src/report/csv_report.dart';
export 'src/report/json_report.dart';
export 'src/report/log_writer.dart';
export 'src/scan/orchestrator.dart';
export 'src/source/engine_observation_source.dart';
export 'src/source/fixture_observation_source.dart';
export 'src/source/observation_source.dart';
