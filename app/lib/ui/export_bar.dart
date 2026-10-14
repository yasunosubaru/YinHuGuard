// app/lib/ui/export_bar.dart
//
// 底部的导出栏。三个按钮：JSON、CSV、重扫。
//
// 导出目标是程序旁边的 reports 目录。刻意不做「另存为」对话框：
// 那需要一个平台插件，而它换来的只是少一次复制路径。写失败时回退到
// 用户文档目录，并把真实路径显示出来 —— 路径必须可见，否则用户找不到文件。

import 'package:flutter/material.dart';

import '../strings.dart';

class ExportBar extends StatelessWidget {
  final bool enabled;
  final VoidCallback onExportJson;
  final VoidCallback onExportCsv;
  final VoidCallback onRescan;

  /// 最近一次导出/日志的落点，显示给用户。
  final String? lastPath;

  const ExportBar({
    super.key,
    required this.enabled,
    required this.onExportJson,
    required this.onExportCsv,
    required this.onRescan,
    this.lastPath,
  });

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    return Material(
      color: theme.colorScheme.surfaceContainerHigh,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(
          children: <Widget>[
            OutlinedButton.icon(
              onPressed: enabled ? onExportJson : null,
              icon: const Icon(Icons.data_object),
              label: const Text(kExportJson),
            ),
            const SizedBox(width: 8),
            OutlinedButton.icon(
              onPressed: enabled ? onExportCsv : null,
              icon: const Icon(Icons.table_chart_outlined),
              label: const Text(kExportCsv),
            ),
            const SizedBox(width: 16),
            FilledButton.icon(
              onPressed: onRescan,
              icon: const Icon(Icons.refresh),
              label: const Text(kRescan),
            ),
            const SizedBox(width: 16),
            Expanded(
              child: lastPath == null
                  ? const SizedBox.shrink()
                  : SelectableText(
                      lastPath!,
                      maxLines: 2,
                      style: theme.textTheme.bodySmall,
                    ),
            ),
          ],
        ),
      ),
    );
  }
}
