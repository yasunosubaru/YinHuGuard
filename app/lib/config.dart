// app/lib/config.dart
//
// 启动参数与路径解析。放在一处，因为这两件事都容易「静默走偏」：
// 参数拼错不至于崩，但会让程序去找错的配置；路径猜错会让引擎报
// 「无法打开配置文件」，看起来像配置坏了而实际是路径算错了。
//
// 整包根目录的解析沿用一条硬规则：**从 exe 向上找同时含 rules/ 与引擎 DLL
// 的目录**，不靠 `<仓库上级>\YinHuGuard` 这类猜测。这个仓库和构建产物
// 会分别落在不同的卷上，任何按固定层级猜路径的写法都会静默走偏。

import 'dart:io';

class AppPaths {
  final String configPath;
  final String dllPath;

  /// 非空时走合成 fixture 而不是真实引擎 —— 开发与验证用，
  /// 也是「不碰用户机器」这条约束唯一被允许的执行方式。
  final String? fixturePath;

  const AppPaths({
    required this.configPath,
    required this.dllPath,
    this.fixturePath,
  });

  bool get usesFixture => fixturePath != null && fixturePath!.isNotEmpty;
}

class AppArgs {
  final List<String> raw;
  const AppArgs(this.raw);

  String? _valueOf(String flag) {
    final int at = raw.indexOf(flag);
    if (at < 0 || at + 1 >= raw.length) {
      return null;
    }
    return raw[at + 1];
  }

  bool get hasFixture => raw.contains('--fixture');
  String? get fixturePath => _valueOf('--fixture');
  String? get configPath => _valueOf('--config');
  String? get dllPath => _valueOf('--dll');
}

/// 引擎 DLL 的文件名。打包后与 exe 同级；开发时在 engine/build/Release 下。
const String kEngineDllName = 'yinhuguard_engine.dll';

/// 从 [startDir] 向上逐级寻找「整包根」：同时含有 `rules/rules.json`
/// 与引擎 DLL 的目录。找不到返回 null，由调用方给出明确错误而不是猜一个。
String? resolveBundleRoot(String startDir) {
  Directory current = Directory(startDir).absolute;
  for (int depth = 0; depth < 12; depth++) {
    final bool hasRules = File(
      '${current.path}${Platform.pathSeparator}rules${Platform.pathSeparator}rules.json',
    ).existsSync();
    final bool hasDll = _findDllIn(current) != null;
    if (hasRules && hasDll) {
      return current.path;
    }
    // Directory.parent 在到达卷根时返回自身（非 null），所以用路径相等判断终止。
    final Directory parent = current.parent;
    if (parent.path == current.path) {
      break;
    }
    current = parent;
  }
  return null;
}

String? _findDllIn(Directory dir) {
  final List<String> candidates = <String>[
    dir.path,
    '${dir.path}${Platform.pathSeparator}bin',
    '${dir.path}${Platform.pathSeparator}engine${Platform.pathSeparator}build'
        '${Platform.pathSeparator}Release',
  ];
  for (final String candidate in candidates) {
    final String path = '$candidate${Platform.pathSeparator}$kEngineDllName';
    if (File(path).existsSync()) {
      return path;
    }
  }
  return null;
}

/// 解析出可用路径。任何一项定不下来就抛 [ConfigException]，把「该给什么参数」
/// 写清楚 —— 猜一个路径然后报「配置文件无效」是最难查的一类故障。
AppPaths resolvePaths(AppArgs args, {String? executableDir}) {
  final String exeDir =
      executableDir ?? File(Platform.resolvedExecutable).parent.path;

  final String? explicitConfig = args.configPath;
  final String? explicitDll = args.dllPath;

  final String? root = resolveBundleRoot(exeDir);

  String? configPath = explicitConfig;
  if (configPath == null) {
    final String besideExe = '$exeDir${Platform.pathSeparator}rules.json';
    if (File(besideExe).existsSync()) {
      configPath = besideExe;
    } else if (root != null) {
      configPath =
          '$root${Platform.pathSeparator}rules${Platform.pathSeparator}rules.json';
    }
  }

  String? dllPath = explicitDll;
  if (dllPath == null) {
    dllPath = _findDllIn(Directory(exeDir));
    if (dllPath == null && root != null) {
      dllPath = _findDllIn(Directory(root));
    }
  }

  if (configPath == null || !File(configPath).existsSync()) {
    throw ConfigException(
      '找不到配置文件 rules.json。\n'
      '可以放在程序旁边，或用 --config <路径> 指定。\n'
      '当前查找起点：$exeDir',
    );
  }
  if (dllPath == null || !File(dllPath).existsSync()) {
    throw ConfigException(
      '找不到引擎 $kEngineDllName。\n'
      '可以放在程序旁边，或用 --dll <路径> 指定。\n'
      '当前查找起点：$exeDir',
    );
  }

  return AppPaths(configPath: configPath, dllPath: dllPath, fixturePath: args.fixturePath);
}

class ConfigException implements Exception {
  final String message;
  ConfigException(this.message);
  @override
  String toString() => message;
}
