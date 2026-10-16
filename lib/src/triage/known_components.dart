// lib/src/triage/known_components.dart
//
// 未覆盖条目的自动对照清单。真机上「未覆盖」动辄三四十条，而其中真正需要
// 人看一眼的往往只有一两条 —— 这一层就是把那几条挑出来。
//
// 三条自我约束（改动前先读）：
//
//   1) **只按名字比对。** 未覆盖条目恰恰是路径读不到的那些，拿不到路径、签名、
//      哈希，能比的只有名字。所以命中一律要说成「已对照，名字眼熟」，不能
//      说成「这是安全的」—— 文案里必须带「仅名字比对，无法进一步验证」。
//
//   2) **永不隐藏、永不改判定。** 命中只加标注与计数：条目照旧留在列表里，
//      照旧算未覆盖，照旧不放行。名字可以被伪装，把命中当放行就是在给伪装
//      开绿灯 —— 那比不做这个功能更糟。
//
//   3) **名单宁缺勿滥。** 查不到可靠归属的名字一律不收录，让它留在
//      「待人工核实」。少收一条的代价是用户多看一条；错收一条的代价是
//      伪装成系统进程的样本被标成「已知组件」。
//
// 数据在 rules.json 的 known_components 段（引擎会跳过不认识的键，所以加这一段
// 不需要改 C++）。

/// 组件的归属类别。决定文案与颜色，不决定放行与否 —— 没有任何一类会放行。
enum KnownKind { windows, vendor }

class KnownComponent {
  final KnownKind kind;

  /// 文案用的归属说明。Windows 组件是固定说法；第三方带上厂商与用途，
  /// 例如「Intel PresentMon（性能监测）」。
  final String label;

  const KnownComponent(this.kind, this.label);

  bool get isWindows => kind == KnownKind.windows;
}

class KnownComponents {
  final Set<String> windowsProcesses;
  final Set<String> windowsDrivers;
  final Set<String> windowsServices;

  /// 名字（小写）→ 厂商说明。
  final Map<String, String> vendorProcesses;
  final Map<String, String> vendorServices;

  const KnownComponents({
    this.windowsProcesses = const <String>{},
    this.windowsDrivers = const <String>{},
    this.windowsServices = const <String>{},
    this.vendorProcesses = const <String, String>{},
    this.vendorServices = const <String, String>{},
  });

  static const KnownComponent kWindowsLabel =
      KnownComponent(KnownKind.windows, 'Windows 系统组件');

  /// 读 rules.json 的 `known_components` 段。
  ///
  /// 缺失或形状不对时返回空清单，**不报错**：与 `process_allowlist` 同一策略 ——
  /// 少一份分诊清单只会让列表更长，不会让结论变错；为此拒绝启动是不成比例的。
  factory KnownComponents.fromRules(Map<String, dynamic> rules) {
    final Object? section = rules['known_components'];
    if (section is! Map<String, dynamic>) {
      return const KnownComponents();
    }
    final Map<String, dynamic> windows = _asMap(section['windows']);
    final Map<String, dynamic> vendor = _asMap(section['vendor']);
    return KnownComponents(
      windowsProcesses: _names(windows['processes']),
      windowsDrivers: _names(windows['drivers']),
      windowsServices: _names(windows['services']),
      vendorProcesses: _attributed(vendor['processes']),
      vendorServices: _attributed(vendor['services']),
    );
  }

  /// 按扫描面查一个名字。[name] 可以是完整路径，取最后一段比对。
  ///
  /// 返回 null 表示不在清单里（= 待人工核实），调用方不要把它当成错误。
  KnownComponent? lookup(String surface, String name) {
    final String key = _normalize(name);
    if (key.isEmpty) {
      return null;
    }
    final Set<String>? windows = switch (surface) {
      'processes' => windowsProcesses,
      'drivers' => windowsDrivers,
      'services' => windowsServices,
      _ => null,
    };
    if (windows != null && windows.contains(key)) {
      return kWindowsLabel;
    }
    final Map<String, String>? vendor = switch (surface) {
      'processes' => vendorProcesses,
      'services' => vendorServices,
      _ => null,
    };
    final String? label = vendor?[key];
    if (label != null && label.isNotEmpty) {
      return KnownComponent(KnownKind.vendor, label);
    }
    return null;
  }

  /// 清单是否为空（数据缺失时会是这样）。界面用它决定要不要显示分诊提示。
  bool get isEmpty =>
      windowsProcesses.isEmpty &&
      windowsDrivers.isEmpty &&
      windowsServices.isEmpty &&
      vendorProcesses.isEmpty &&
      vendorServices.isEmpty;
}

/// 取文件名（同时接受 `\` 与 `/`）、去首尾空白、转小写 —— 与白名单折叠
/// （evaluator 的 basenameOf）保持同一套归一化，免得两处规则不一致。
String _normalize(String raw) {
  final String trimmed = raw.trim();
  final int cut = trimmed.lastIndexOf(RegExp(r'[\\/]'));
  final String base = cut < 0 ? trimmed : trimmed.substring(cut + 1);
  return base.toLowerCase();
}

Map<String, dynamic> _asMap(Object? value) =>
    value is Map<String, dynamic> ? value : const <String, dynamic>{};

Set<String> _names(Object? raw) {
  if (raw is! List) {
    return const <String>{};
  }
  final Set<String> out = <String>{};
  for (final Object? entry in raw) {
    if (entry is String) {
      final String name = _normalize(entry);
      if (name.isNotEmpty) {
        out.add(name);
      }
    }
  }
  return out;
}

Map<String, String> _attributed(Object? raw) {
  if (raw is! Map<String, dynamic>) {
    return const <String, String>{};
  }
  final Map<String, String> out = <String, String>{};
  for (final MapEntry<String, dynamic> entry in raw.entries) {
    final Object? label = entry.value;
    if (label is String && label.isNotEmpty) {
      final String name = _normalize(entry.key);
      if (name.isNotEmpty) {
        out[name] = label;
      }
    }
  }
  return out;
}
