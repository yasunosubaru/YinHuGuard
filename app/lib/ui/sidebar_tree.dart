// app/lib/ui/sidebar_tree.dart
//
// 左侧的七个扫描面。用途是**切换查看**，不是控制扫不扫 —— 所有面总是一起跑
// （上游 bat 也是连着跑完三段），把它们拆成可单独触发只会让人以为
// 「我只扫了服务就等于扫过了」。
//
// 前三个面是上游 bat 的三段（对应关系写在各自的 sub 文案里），
// 后四个是二期深扫面。

import 'package:flutter/material.dart';

import '../strings.dart';

class SurfaceEntry {
  final String key;
  final String label;
  final String sub;
  const SurfaceEntry(this.key, this.label, this.sub);
}

const List<SurfaceEntry> kSurfaceEntries = <SurfaceEntry>[
  SurfaceEntry('processes', kSurfaceProcesses, kSurfaceProcessesSub),
  SurfaceEntry('run_keys', kSurfaceRunKeys, kSurfaceRunKeysSub),
  SurfaceEntry('services', kSurfaceServices, kSurfaceServicesSub),
  // ---- 二期深度扫描 ----
  SurfaceEntry('registry_payloads', kSurfaceRegistryPayloads, kSurfaceRegistryPayloadsSub),
  SurfaceEntry('drivers', kSurfaceDrivers, kSurfaceDriversSub),
  SurfaceEntry('file_drops', kSurfaceFileDrops, kSurfaceFileDropsSub),
  SurfaceEntry('scheduled_tasks', kSurfaceScheduledTasks, kSurfaceScheduledTasksSub),
];

class SidebarTree extends StatelessWidget {
  final String? selected;
  final Map<String, int> hitCounts;
  final Map<String, int> uncoveredCounts;

  /// 本次扫描是否已提权。已提权时「未覆盖」计数不再是可行动缺口
  /// （提权也解决不了），所以不再用错误色 —— 只是如实提示数量。
  final bool elevated;

  final ValueChanged<String?> onSelect;

  const SidebarTree({
    super.key,
    required this.selected,
    required this.hitCounts,
    required this.uncoveredCounts,
    this.elevated = false,
    required this.onSelect,
  });

  @override
  Widget build(BuildContext context) {
    final ThemeData theme = Theme.of(context);
    return SizedBox(
      width: 260,
      child: ListView(
        padding: const EdgeInsets.symmetric(vertical: 8),
        children: <Widget>[
          ListTile(
            dense: true,
            selected: selected == null,
            title: const Text(kSurfaceAll),
            onTap: () => onSelect(null),
          ),
          const Divider(height: 1),
          for (final SurfaceEntry entry in kSurfaceEntries)
            ListTile(
              selected: selected == entry.key,
              onTap: () => onSelect(entry.key),
              title: Text(entry.label),
              subtitle: Text(
                entry.sub,
                style: theme.textTheme.bodySmall,
              ),
              trailing: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.end,
                children: <Widget>[
                  Text(
                    '${hitCounts[entry.key] ?? 0}',
                    style: theme.textTheme.titleMedium,
                  ),
                  if ((uncoveredCounts[entry.key] ?? 0) > 0)
                    Text(
                      '未覆盖 ${uncoveredCounts[entry.key]}',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: elevated
                            ? theme.colorScheme.outline
                            : theme.colorScheme.error,
                      ),
                    ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}
