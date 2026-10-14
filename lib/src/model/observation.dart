// lib/src/model/observation.dart
//
// 「观测」：引擎或 fixture 报上来的一条原始事实。它与 C++ 侧的 YhFinding
// 一一对应，本身不含任何判断结论 —— 白名单折叠、未覆盖语义、分组都由上层做。
//
// 三个被钉死的取值集合（surface / criteria）是引擎与 Dart 之间的契约：
// C++ 里写的是字面量，Dart 这边不认任何别的值。这里**抛异常**而不是用 assert，
// 因为 release 构建会把 assert 编译掉，那正好是本项目最忌讳的「静默接受坏数据」。

/// 三个扫描面，与 spec §4.1–4.3 及上游 bat 的三段一一对应。
const List<String> kSurfaces = <String>['processes', 'run_keys', 'services'];

/// 三类判据。服务判据有两条，文件属性类共用一条。
const List<String> kCriteria = <String>[
  'file_attr_hs',
  'service_interpreter',
  'service_path_heuristic',
];

/// JSON 用 snake_case（与 rules.json、报告格式一致），Dart 用 camelCase。
/// 映射是显式的，不依赖任何自动转换 —— 字段名一旦漂移，报告就会静默错位。
class Observation {
  final String surface;
  final String locator;
  final String displayName;
  final String criteria;

  /// 本条依据的是否为文件属性，且属性确实读到了。
  /// 服务判据查的是 ImagePath 形状，因此恒为 false；这表示「不依据属性」，
  /// 不是「读失败」——后者由 covered 表达。
  final bool attributesVerified;

  final bool hidden;
  final bool system;
  final bool elevationRequired;

  /// false = 该项因权限或环境原因未被检查。上层必须把它显示成「未覆盖」，
  /// **绝不能**让空结果冒充「干净」。
  final bool covered;

  final DateTime timestamp;

  Observation({
    required this.surface,
    required this.locator,
    required this.displayName,
    required this.criteria,
    required this.attributesVerified,
    required this.hidden,
    required this.system,
    required this.elevationRequired,
    required this.covered,
    required this.timestamp,
  }) {
    if (!kSurfaces.contains(surface)) {
      throw ArgumentError.value(surface, 'surface', '未知扫描面，只接受 $kSurfaces');
    }
    if (!kCriteria.contains(criteria)) {
      throw ArgumentError.value(criteria, 'criteria', '未知判据，只接受 $kCriteria');
    }
  }

  factory Observation.fromJson(Map<String, dynamic> json) {
    return Observation(
      surface: json['surface'] as String,
      locator: json['locator'] as String,
      displayName: json['display_name'] as String,
      criteria: json['criteria'] as String,
      attributesVerified: json['attributes_verified'] as bool,
      hidden: json['hidden'] as bool,
      system: json['system'] as bool,
      elevationRequired: json['elevation_required'] as bool,
      covered: json['covered'] as bool,
      // 引擎给的是 unix 秒（double）。fixture 里写成整数也接受。
      timestamp: DateTime.fromMillisecondsSinceEpoch(
        ((json['timestamp'] as num) * 1000).round(),
        isUtc: true,
      ),
    );
  }

  Map<String, dynamic> toJson() => <String, dynamic>{
        'surface': surface,
        'locator': locator,
        'display_name': displayName,
        'criteria': criteria,
        'attributes_verified': attributesVerified,
        'hidden': hidden,
        'system': system,
        'elevation_required': elevationRequired,
        'covered': covered,
        'timestamp': timestamp.millisecondsSinceEpoch / 1000,
      };
}
