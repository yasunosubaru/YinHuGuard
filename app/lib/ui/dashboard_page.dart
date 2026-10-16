// app/lib/ui/dashboard_page.dart
//
// 单页仪表盘。布局自下而上是：导出栏 / 自检面板 / （侧边栏 + 结果表）。
//
// 两条与安全有关的界面决定，写在这里免得日后被「优化」掉：
//
//   1) **打开时不自动扫描。** 一个安全工具在用户还没点任何东西时就去枚举
//      全机进程与服务，是最容易被当成恶意软件的行为。它也把「我只是想看看
//      这个程序长什么样」变成一个已经发生了的系统访问。
//   2) 引擎句柄**在第一次点扫描时才构造**。所以「打开程序」这件事本身
//      不加载 DLL、不读配置、不碰系统。

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';

import '../config.dart';
import 'package:yinhuguard_core/yinhuguard_core.dart';

import '../strings.dart';
import 'export_bar.dart';
import 'findings_table.dart';
import 'selfcheck_panel.dart';
import 'sidebar_tree.dart';

class DashboardPage extends StatefulWidget {
  final AppPaths paths;
  final List<String> userAllowlist;
  final bool elevateAttempted;
  final VoidCallback? onElevate;

  const DashboardPage({
    super.key,
    required this.paths,
    this.userAllowlist = const <String>[],
    this.elevateAttempted = false,
    this.onElevate,
  });

  @override
  State<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends State<DashboardPage> {
  Orchestrator? _orchestrator;
  String? _selectedSurface;
  String? _error;
  String? _lastPath;
  String _progressLabel = '';
  bool _scanning = false;

  /// 每次点扫描都重建来源。fixture 会重读文件；真实引擎的那次会重开 DLL。
  /// 代价可以忽略，换来的是「打开程序时不碰任何东西」。
  ObservationSource _buildSource() {
    final AppPaths paths = widget.paths;
    if (paths.usesFixture) {
      final String text = File(paths.fixturePath!).readAsStringSync();
      return FixtureObservationSource.fromJson(
        jsonDecode(text) as Map<String, dynamic>,
      );
    }
    return EngineObservationSource(
      dllPath: paths.dllPath,
      configPath: paths.configPath,
    );
  }

  /// 读 rules.json 的 known_components 段：未覆盖条目的名字对照清单。
  /// 读不出来不算错误 —— 与白名单同一策略，少一份分诊清单只会让列表更长。
  KnownComponents _knownComponents() {
    try {
      final Map<String, dynamic> rules = jsonDecode(
        File(widget.paths.configPath).readAsStringSync(),
      ) as Map<String, dynamic>;
      return KnownComponents.fromRules(rules);
    } catch (_) {
      return const KnownComponents();
    }
  }

  Future<void> _runScan() async {
    setState(() {
      _scanning = true;
      _error = null;
      _progressLabel = kScanning;
      _lastPath = null;
    });

    try {
      final ObservationSource source = _buildSource();
      final Orchestrator orchestrator = Orchestrator(
        source,
        userAllowlist: widget.userAllowlist,
        knownComponents: _knownComponents(),
      );
      await orchestrator.scan((String surface, int index, int total) {
        if (!mounted) {
          return;
        }
        final String label = kSurfaceEntries
            .firstWhere(
              (SurfaceEntry e) => e.key == surface,
              orElse: () => SurfaceEntry(surface, surface, ''),
            )
            .label;
        setState(() => _progressLabel = '$kScanning  $label  $index/$total');
      });

      // 日志与扫描同一次落盘：报告可以晚点导出，日志必须现在就有，
      // 否则出问题时对方手里什么都没有。
      final String? logPath = await _writeLog(orchestrator);

      if (!mounted) {
        return;
      }
      setState(() {
        _orchestrator = orchestrator;
        _scanning = false;
        _progressLabel = '';
        _lastPath = logPath;
      });
    } on EngineException catch (e) {
      _fail('$kEngineError: ${e.message}');
    } on ConfigException catch (e) {
      _fail('$kConfigError\n${e.message}');
    } catch (e) {
      _fail('$kEngineError: $e');
    }
  }

  void _fail(String message) {
    if (!mounted) {
      return;
    }
    setState(() {
      _scanning = false;
      _progressLabel = '';
      _error = message;
    });
  }

  /// 写目录优先级：exe 旁边的 reports/ → 用户文档目录。
  /// 便携 zip 通常在可写目录，但装在 Program Files 下时第二个会生效。
  Directory _reportDir() {
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

  Future<String?> _writeLog(Orchestrator orchestrator) async {
    try {
      final File file = await writeScanLog(
        orchestrator.result,
        _reportDir(),
        username: _userName(),
        machineName: _machineName(),
      );
      return '$kLogWritten ${file.path}';
    } catch (_) {
      return null;  // 日志写不出来不该让整个扫描失败
    }
  }

  String _userName() => Platform.environment['USERNAME'] ?? '';

  String _machineName() => Platform.environment['COMPUTERNAME'] ?? '';

  Future<void> _export({required bool json}) async {
    final Orchestrator? orchestrator = _orchestrator;
    if (orchestrator == null) {
      return;
    }
    try {
      final Directory dir = _reportDir();
      // 与日志文件名统一用 UTC：两个文件并排放在同一个目录里，
      // 一个本地时一个 UTC 会让人以为它们是两次不同的扫描。
      final String stamp = DateTime.now().toUtc()
          .toIso8601String()
          .split('.')
          .first
          .replaceAll(':', '-');
      final String name = json ? 'report-$stamp.json' : 'report-$stamp.csv';
      final File file = File('${dir.path}${Platform.pathSeparator}$name');
      final String body = json
          ? toJsonReport(
              orchestrator.result,
              username: _userName(),
              machineName: _machineName(),
            )
          : toCsvReport(
              orchestrator.result,
              username: _userName(),
              machineName: _machineName(),
            );
      await file.writeAsString(body);
      if (!mounted) {
        return;
      }
      setState(() => _lastPath = '$kExportedTo ${file.path}');
    } catch (e) {
      _fail('导出失败：$e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    final Orchestrator? orchestrator = _orchestrator;

    final List<Finding> visible = <Finding>[];
    final Map<String, int> hitCounts = <String, int>{};
    final Map<String, int> uncoveredCounts = <String, int>{};
    int knownTotal = 0;
    int unidentifiedTotal = 0;

    if (orchestrator != null) {
      for (final Finding f in orchestrator.visibleFindings) {
        hitCounts[f.surface] = (hitCounts[f.surface] ?? 0) + 1;
      }
      for (final Finding f in orchestrator.result.findings) {
        if (!f.covered) {
          uncoveredCounts[f.surface] = (uncoveredCounts[f.surface] ?? 0) + 1;
        }
      }
      // 分诊计数：未覆盖里哪些名字已对照上、哪几条对不上（那几条才要人看）。
      knownTotal = knownCountOf(orchestrator.result.findings);
      unidentifiedTotal = unidentifiedCountOf(orchestrator.result.findings);
      visible.addAll(
        _selectedSurface == null
            ? orchestrator.visibleFindings
            : orchestrator.visibleFindings
                .where((Finding f) => f.surface == _selectedSurface),
      );
    }

    return Column(
      children: <Widget>[
        Expanded(
          child: Row(
            children: <Widget>[
              SidebarTree(
                selected: _selectedSurface,
                hitCounts: hitCounts,
                uncoveredCounts: uncoveredCounts,
                // 已提权时「未覆盖」不再是可行动缺口，行内颜色随之转中性。
                elevated: orchestrator?.result.selfCheck.elevated ?? false,
                onSelect: (String? value) =>
                    setState(() => _selectedSurface = value),
              ),
              const VerticalDivider(width: 1),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    SelfCheckPanel(
                      selfCheck: orchestrator?.result.selfCheck,
                      // 传给面板的是发现级的未覆盖总数，不是各面聚合 ——
                      // 聚合数字上看不出某一条具体项没读出来。
                      uncoveredCount: uncoveredCounts.values.fold<int>(
                        0,
                        (int sum, int n) => sum + n,
                      ),
                      knownCount: knownTotal,
                      unidentifiedCount: unidentifiedTotal,
                      elevateAttempted: widget.elevateAttempted,
                      onElevate: widget.onElevate,
                    ),
                    if (_error != null)
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 12),
                        child: Card(
                          color: theme.colorScheme.errorContainer,
                          child: Padding(
                            padding: const EdgeInsets.all(12),
                            child: Text(
                              _error!,
                              style: TextStyle(
                                color: theme.colorScheme.onErrorContainer,
                              ),
                            ),
                          ),
                        ),
                      ),
                    Expanded(child: _body(orchestrator, visible)),
                  ],
                ),
              ),
            ],
          ),
        ),
        if (_scanning)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            child: Row(
              children: <Widget>[
                const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
                const SizedBox(width: 12),
                Text(_progressLabel),
                const Spacer(),
                // 无倒计时的进度条是最常见的弃用原因，所以这里显式带上进度语义。
                Text(kScanProgressHint),
              ],
            ),
          ),
        ExportBar(
          enabled: !_scanning && orchestrator != null,
          onExportJson: () => _export(json: true),
          onExportCsv: () => _export(json: false),
          onRescan: _runScan,
          lastPath: _lastPath,
        ),
      ],
    );
  }

  Widget _body(Orchestrator? orchestrator, List<Finding> visible) {
    if (_scanning) {
      return const Center(child: Text(kScanning));
    }
    if (orchestrator == null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            const Text(kNoScanYet),
            const SizedBox(height: 12),
            FilledButton(onPressed: _runScan, child: const Text(kStartScan)),
            const SizedBox(height: 8),
            if (widget.paths.usesFixture)
              Text(
                '（fixture 模式：${widget.paths.fixturePath}）',
                style: Theme.of(context).textTheme.bodySmall,
              ),
          ],
        ),
      );
    }
    return FindingsTable(
      findings: visible.cast<Finding>(),
      // 行内措辞要看提权状态：已提权时 ACCESS_DENIED 只能是系统保护。
      elevated: orchestrator.result.selfCheck.elevated,
    );
  }
}
