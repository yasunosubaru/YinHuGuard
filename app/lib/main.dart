// app/lib/main.dart
//
// 启动入口。这里只做三件事：解析参数、解析路径、把界面挂起来。
//
// 刻意**不在这里**构造观测来源：路径解析会读文件（配置文件是否存在），
// 但加载 DLL、读配置内容、枚举系统都推迟到用户点「开始扫描」。
// 「打开这个程序」本身不应该碰到系统。

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

import 'cli.dart';
import 'config.dart';
import 'elevate.dart';
import 'headless.dart';
import 'strings.dart';
import 'ui/dashboard_page.dart';

Future<void> main(List<String> args) async {
  switch (parseArgs(args)) {
    case InvalidArgs(:final String message):
      stderr.writeln(message);
      stderr.writeln('用法: yinhuguard_app.exe [--scan] [--json <路径>] '
          '[--fixture <路径>] [--config <路径>] [--dll <路径>]');
      exitCode = 1;
      return;
    case RunScan(:final String? jsonOutPath):
      // 无界面路径：不初始化 Flutter binding，直接跑扫描。
      final int code = await runHeadlessScan(AppArgs(args), jsonOutPath);
      // **必须显式 exit**，不能只设 exitCode 然后 return。
      // Flutter 的 Windows 产物是 GUI 子系统程序，embedder 在 Dart main 返回后
      // 仍然跑着自己的消息循环，进程不会自己结束 —— 只设退出码的话命令行会
      // 一直挂着不返回。exit() 直接终止进程，把码带出去。
      exit(code);
    case RunGui():
      WidgetsFlutterBinding.ensureInitialized();
      runApp(YinHuGuardApp(appArgs: AppArgs(args)));
  }
}

class YinHuGuardApp extends StatelessWidget {
  final AppArgs appArgs;
  const YinHuGuardApp({super.key, required this.appArgs});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: kAppTitle,
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: const Color(0xFF37507A),
        useMaterial3: true,
      ),
      home: _Bootstrap(appArgs: appArgs),
    );
  }
}

class _Bootstrap extends StatefulWidget {
  final AppArgs appArgs;
  const _Bootstrap({required this.appArgs});

  @override
  State<_Bootstrap> createState() => _BootstrapState();
}

class _BootstrapState extends State<_Bootstrap> {
  AppPaths? _paths;
  String? _error;
  bool _elevateAttempted = false;

  @override
  void initState() {
    super.initState();
    _elevateAttempted = alreadyRelaunched(widget.appArgs.raw);
    try {
      _paths = resolvePaths(widget.appArgs);
    } on ConfigException catch (e) {
      _error = '$kConfigError\n\n${e.message}';
    } catch (e) {
      _error = '$kConfigError\n\n$e';
    }
  }

  /// 读 rules.json 里的 process_allowlist 当作内置用户白名单。
  /// 读不出来不算错误：白名单缺失只会让列表更长，不会让结论变错。
  List<String> _loadAllowlist() {
    try {
      final Map<String, dynamic> rules =
          jsonDecode(File(_paths!.configPath).readAsStringSync()) as Map<String, dynamic>;
      final Object? list = rules['process_allowlist'];
      if (list is List) {
        return list.cast<String>();
      }
    } catch (_) {
      // 忽略
    }
    return const <String>[];
  }

  void _elevate() {
    setState(() => _elevateAttempted = true);
    final ElevateResult result = relaunchElevated(
      widget.appArgs.raw,
      exePath: Platform.resolvedExecutable,
    );
    if (result == ElevateResult.launched) {
      // 新实例接管，当前实例让位。
      exit(0);
    }
    // cancelled / failed 都保持当前实例运行，界面上的未覆盖提示因此继续成立 ——
    // 提权没成功绝不能把结论变成看起来完整。
  }

  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return Scaffold(
        appBar: AppBar(title: const Text(kAppTitle)),
        body: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Text(kConfigError,
                  style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 8),
              Text(kConfigErrorHint),
              const SizedBox(height: 16),
              Expanded(child: SelectableText(_error!)),
            ],
          ),
        ),
      );
    }

    final AppPaths paths = _paths!;
    return Scaffold(
      appBar: AppBar(
        title: const Text(kAppTitle),
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(20),
          child: Padding(
            padding: const EdgeInsets.only(left: 16, bottom: 6),
            child: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                kAppSubtitle,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
          ),
        ),
      ),
      body: Column(
        children: <Widget>[
          Expanded(
            child: DashboardPage(
              paths: paths,
              userAllowlist: _loadAllowlist(),
              elevateAttempted: _elevateAttempted,
              // 未提权时才提供提权入口；已提权则界面会给「覆盖完整」的提示。
              onElevate: isElevated() ? null : _elevate,
            ),
          ),
          Material(
            color: Theme.of(context).colorScheme.surfaceContainerLow,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  kSmartScreenHint,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
