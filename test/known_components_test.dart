// test/known_components_test.dart
//
// 未覆盖条目的自动对照。两条铁律：
//   1) 命中只加标注，绝不放行 —— covered 不变、不折叠、不改判定；
//   2) 名单宁缺勿滥 —— 对不上的名字必须留在「待人工核实」。
//
// 最后一组用的是 2026-10-16 07:59:55 本机真机提权扫描的**实际未覆盖名单**
// （日志：dist/yinhuguard/reports/yinhuguard-2026-10-16T07-59-55.log，
// 26 个进程 + 12 个驱动）。名单数据改坏了这一组会立刻红。

import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:yinhuguard_core/src/criteria/evaluator.dart';
import 'package:yinhuguard_core/src/model/finding.dart';
import 'package:yinhuguard_core/src/model/observation.dart';
import 'package:yinhuguard_core/src/triage/known_components.dart';

KnownComponents loadKnown() {
  final String text = File('rules/rules.json').readAsStringSync();
  return KnownComponents.fromRules(jsonDecode(text) as Map<String, dynamic>);
}

Observation uncoveredProcess(String name) => Observation(
      surface: 'processes',
      locator: name,
      displayName: name,
      criteria: 'file_attr_hs',
      attributesVerified: false,
      hidden: false,
      system: false,
      elevationRequired: true,
      covered: false,
      timestamp: DateTime.utc(2026, 10, 16),
    );

void main() {
  group('匹配规则', () {
    test('大小写、首尾空白、完整路径都能归一化', () {
      final KnownComponents known = loadKnown();
      expect(known.lookup('processes', 'CSRSS.EXE')?.isWindows, isTrue);
      expect(known.lookup('processes', r'C:\Windows\System32\csrss.exe')?.isWindows, isTrue);
      expect(known.lookup('processes', '  dwm.exe  ')?.isWindows, isTrue);
    });

    test('伪进程名（含空格与方括号）也能对上', () {
      final KnownComponents known = loadKnown();
      for (final String name in <String>[
        '[System Process]',
        'System',
        'Secure System',
        'Registry',
        'Memory Compression',
      ]) {
        expect(known.lookup('processes', name)?.isWindows, isTrue, reason: name);
      }
    });

    test('第三方组件带厂商说明，且不算 Windows 组件', () {
      final KnownComponent? found = loadKnown().lookup('processes', 'PresentMonService.exe');
      expect(found, isNotNull);
      expect(found!.isWindows, isFalse);
      expect(found.label, contains('Intel'));
    });

    test('按扫描面区分：驱动名不会在进程面被认下来', () {
      final KnownComponents known = loadKnown();
      expect(known.lookup('drivers', 'Ntfs')?.isWindows, isTrue);
      expect(known.lookup('processes', 'Ntfs'), isNull);
    });

    test('清单缺失或形状不对 → 空清单，不抛异常', () {
      expect(KnownComponents.fromRules(<String, dynamic>{}).isEmpty, isTrue);
      expect(
        KnownComponents.fromRules(<String, dynamic>{'known_components': 3}).isEmpty,
        isTrue,
      );
      expect(
        KnownComponents.fromRules(<String, dynamic>{
          'known_components': <String, dynamic>{
            'windows': <String, dynamic>{
              'processes': <int>[1],
            },
          },
        }).isEmpty,
        isTrue,
      );
    });
  });

  group('真机名单（2026-10-16 07:59:55 提权实测，一字不改抄自日志）', () {
    const List<String> measuredProcesses = <String>[
      '[System Process]',
      'System',
      'Secure System',
      'Registry',
      'csrss.exe',
      'fontdrvhost.exe',
      'WUDFHost.exe',
      'dwm.exe',
      'Memory Compression',
      'WUDFCompanionHost.exe',
      'AggregatorHost.exe',
      'NgcIso.exe',
      'dasHost.exe',
      'WmiPrvSE.exe',
      'unsecapp.exe',
      'iGoSwServer.exe',
      'PresentMonService.exe',
      'conhost.exe',
      'wlanext.exe',
      'SearchFilterHost.exe',
      'vmwp.exe',
      'vmmemWSA',
      'dllhost.exe',
      'IntelGraphicsSoftware.Service.Graphics.exe',
      'ctfmon.exe',
      'ChsIME.exe',
    ];

    const List<String> measuredDrivers = <String>[
      'Beep',
      'CimFS',
      'exfat',
      'fastfat',
      'Msfs',
      'MsRPC',
      'Npfs',
      'Ntfs',
      'Null',
      'ReFS',
      'ReFSv1',
      'Wof',
    ];

    test('38 条里只有 iGoSwServer.exe 对不上 —— 其余都必须归好类', () {
      final KnownComponents known = loadKnown();

      final List<String> unidentified = <String>[
        for (final String n in measuredProcesses)
          if (known.lookup('processes', n) == null) n,
        for (final String n in measuredDrivers)
          if (known.lookup('drivers', n) == null) n,
      ];
      expect(unidentified, <String>['iGoSwServer.exe'],
          reason: '查不到归属的名字不许收进清单，只能留在「待人工核实」');

      int windows = 0;
      int vendor = 0;
      for (final String n in measuredProcesses) {
        final KnownComponent? found = known.lookup('processes', n);
        if (found?.isWindows ?? false) {
          windows += 1;
        } else if (found != null) {
          vendor += 1;
        }
      }
      expect(windows, 23, reason: '26 条进程里 23 条是 Windows 组件');
      expect(vendor, 2, reason: '另 2 条是已识别的第三方（Intel 两项）');
      expect(
        measuredDrivers.where((String n) => known.lookup('drivers', n) == null),
        isEmpty,
        reason: '12 条驱动全是微软自带文件系统/过滤驱动',
      );
      expect(measuredProcesses.length + measuredDrivers.length, 38);
    });

    test('对照不改变判定：命中已知组件照旧是未覆盖、照旧不折叠', () {
      final List<Finding> findings = evaluate(
        <Observation>[uncoveredProcess('csrss.exe')],
        userAllowlist: const <String>[],
        knownComponents: loadKnown(),
      );

      expect(findings.single.covered, isFalse, reason: '读不到就是读不到');
      expect(findings.single.allowlisted, isFalse, reason: '名字眼熟不等于放行');
      expect(findings.single.known, isNotNull);
      expect(uncoveredCountOf(findings), 1);
      expect(knownCountOf(findings), 1);
      expect(unidentifiedCountOf(findings), 0);
    });

    test('对不上的名字落到 unidentified 计数里', () {
      final List<Finding> findings = evaluate(
        <Observation>[
          uncoveredProcess('csrss.exe'),
          uncoveredProcess('iGoSwServer.exe'),
        ],
        userAllowlist: const <String>[],
        knownComponents: loadKnown(),
      );

      expect(findings.last.known, isNull);
      expect(knownCountOf(findings), 1);
      expect(unidentifiedCountOf(findings), 1);
      expect(uncoveredCountOf(findings), 2);
    });

    test('已覆盖的条目不做对照：判据已经给过答案，再加「名字眼熟」只会稀释信号', () {
      final Observation covered = Observation(
        surface: 'processes',
        locator: 'csrss.exe',
        displayName: 'csrss.exe',
        criteria: 'file_attr_hs',
        attributesVerified: true,
        hidden: true,
        system: false,
        elevationRequired: false,
        covered: true,
        timestamp: DateTime.utc(2026, 10, 16),
      );

      final List<Finding> findings = evaluate(
        <Observation>[covered],
        userAllowlist: const <String>[],
        knownComponents: loadKnown(),
      );

      expect(findings.single.known, isNull);
    });

    test('清单缺失时对照为空 —— 界面上退回「只有未覆盖计数」的老行为', () {
      final List<Finding> findings = evaluate(
        <Observation>[uncoveredProcess('csrss.exe')],
        userAllowlist: const <String>[],
      );

      expect(findings.single.known, isNull);
      expect(knownCountOf(findings), 0);
      expect(unidentifiedCountOf(findings), 1);
    });
  });
}
