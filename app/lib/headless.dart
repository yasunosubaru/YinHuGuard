// app/lib/headless.dart
//
// 无界面扫描。供 --scan / --json 使用。
//
// 与界面走的是同一套编排与同一份报告代码 —— 输出同源是硬要求，
// 否则「命令行说没问题、界面上却有命中」这种事迟早会发生，
// 而它会让所有自动化判断失效。

import 'dart:convert';
import 'dart:io';

import 'package:yinhuguard_core/yinhuguard_core.dart';

import 'cli.dart';
import 'config.dart';
import 'strings.dart';

/// 退出码，与 cli.dart 的注释一致。
const int kExitOk = 0;
const int kExitEngineError = 2;
const int kExitPathError = 3;
const int kExitFindings = 10;

Future<int> runHeadlessScan(AppArgs args, String? jsonOutPath) async {
  final AppPaths paths;
  try {
    paths = resolvePaths(args);
  } on ConfigException catch (e) {
    await _emit('$kConfigError\n${e.message}\n');
    return kExitPathError;
  }

  final ObservationSource source;
  try {
    if (paths.usesFixture) {
      source = FixtureObservationSource.fromJson(
        jsonDecode(File(paths.fixturePath!).readAsStringSync()) as Map<String, dynamic>,
      );
    } else {
      source = EngineObservationSource(
        dllPath: paths.dllPath,
        configPath: paths.configPath,
      );
    }
  } catch (e) {
    await _emit('无法准备观测来源：$e\n');
    return kExitPathError;
  }

  final Orchestrator orchestrator = Orchestrator(
    source,
    userAllowlist: _allowlistFromConfig(paths.configPath),
  );

  try {
    await orchestrator.scan((_, __, ___) {});
  } on EngineException catch (e) {
    await _emit('$kEngineError: ${e.message}\n');
    return kExitEngineError;
  } catch (e) {
    await _emit('$kEngineError: $e\n');
    return kExitEngineError;
  }

  final ScanResult result = orchestrator.result;
  final String json = toJsonReport(
    result,
    username: _userName(),
    machineName: _machineName(),
  );

  final Directory outDir = _outputDir(jsonOutPath);
  final String stamp =
      DateTime.now().toUtc().toIso8601String().split('.').first.replaceAll(':', '-');
  final String jsonPath = jsonOutPath ??
      '${outDir.path}${Platform.pathSeparator}report-$stamp.json';

  await File(jsonPath).writeAsString(json);
  final File logFile = await writeScanLog(
    result,
    outDir,
    username: _userName(),
    machineName: _machineName(),
  );

  await _emit(_summary(result, jsonPath, logFile.path));
  return result.findings.isEmpty ? kExitOk : kExitFindings;
}

/// 摘要刻意先讲「未覆盖」再讲命中 —— 读者拿到一段文字时，
/// 第一句先看到的应该是结论的适用边界，而不是数字。
String _summary(ScanResult result, String jsonPath, String logPath) {
  final int uncovered = uncoveredCountOf(result.findings);
  final StringBuffer out = StringBuffer();
  out.writeln('YinHuGuard 扫描完成');
  out.writeln('----------------------------------------');
  out.writeln('管理员权限: ${result.selfCheck.elevated ? kYes : kNo}');
  out.writeln('进程 ${result.selfCheck.processTotal} 个，取到路径 '
      '${result.selfCheck.processPathResolved} 个，'
      'Session 0 可见 ${result.selfCheck.session0Visible} 个');
  out.writeln('服务 ${result.selfCheck.servicesTotal} 个，取到 ImagePath '
      '${result.selfCheck.servicesWithPath} 个');
  out.writeln();
  for (final String surface in kScanOrder) {
    final int n = result.findings.where((Finding f) => f.surface == surface).length;
    out.writeln('  $surface: $n 条');
  }
  out.writeln();
  out.writeln('发现合计 ${result.findings.length} 条，其中未覆盖 $uncovered 条');
  // 与界面、日志同源：只有**权限缺口**才叫「不完整」。残留（扫描瞬间退出、
  // 保护进程）同样会产出 covered=false 的发现，把它算进来就会出现
  // 「界面说正常残留、命令行说不完整」这种两边打架的输出。
  if (result.selfCheck.hasPermissionGap) {
    out.writeln('!! 本次扫描的覆盖范围不完整。');
    if (!result.selfCheck.elevated) {
      out.writeln('!! 未提权，Session 0 的进程路径读不到，系统进程这一整块没有被检查。');
    }
    // 与日志同一行文案（log_writer）：给出规模，而不是只说「不完整」——
    // 「258 个没检查」和「3 个没检查」在远程排障时不是同一件事。
    out.writeln('!! 有 ${result.selfCheck.permissionGaps} 个进程/服务因权限没被检查。');
    out.writeln('!! 不能据此判断机器干净。');
    out.writeln('!! 需要完整覆盖请以管理员身份重新运行。');
  }
  if (result.selfCheck.hasResidual) {
    out.writeln('（另有 ${result.selfCheck.residualGaps} 个进程/服务在扫描期间退出或受保护，'
        '属正常现象，不影响结论。）');
  }
  for (final Finding f in result.findings) {
    final String flags = <String>[
      f.surface,
      f.criteria,
      if (!f.covered) 'UNCOVERED' else 'covered',
      if (f.allowlisted) 'allowlisted',
    ].join(' ');
    out.writeln('[$flags] ${f.locator}');
  }
  out.writeln('----------------------------------------');
  out.writeln('JSON 报告: $jsonPath');
  out.writeln('日志: $logPath');
  return out.toString();
}

Future<void> _emit(String text) async {
  await writeToConsole(text);
}

Directory _outputDir(String? jsonOutPath) {
  if (jsonOutPath != null) {
    final Directory parent = File(jsonOutPath).absolute.parent;
    parent.createSync(recursive: true);
    return parent;
  }
  final Directory besideExe = Directory(
    '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}reports',
  );
  try {
    besideExe.createSync(recursive: true);
    return besideExe;
  } on FileSystemException {
    final Directory fallback = Directory(
      '${Platform.environment['USERPROFILE']}${Platform.pathSeparator}'
      'Documents${Platform.pathSeparator}YinHuGuard',
    );
    fallback.createSync(recursive: true);
    return fallback;
  }
}

List<String> _allowlistFromConfig(String configPath) {
  try {
    final Map<String, dynamic> rules =
        jsonDecode(File(configPath).readAsStringSync()) as Map<String, dynamic>;
    final Object? list = rules['process_allowlist'];
    if (list is List) {
      return list.cast<String>();
    }
  } catch (_) {
    // 白名单读不出来只会让列表更长，不会让结论变错，不必因此失败。
  }
  return const <String>[];
}

String _userName() => Platform.environment['USERNAME'] ?? '';
String _machineName() => Platform.environment['COMPUTERNAME'] ?? '';
