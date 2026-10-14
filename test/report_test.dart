import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:yinhuguard_core/src/report/csv_report.dart';
import 'package:yinhuguard_core/src/report/json_report.dart';
import 'package:yinhuguard_core/src/report/log_writer.dart';
import 'package:yinhuguard_core/src/scan/orchestrator.dart';
import 'package:yinhuguard_core/src/source/fixture_observation_source.dart';

const String kUser = 'zhangwei';
const String kMachine = 'TEST-PC';

Future<Orchestrator> runFixture(String name, {List<String> allowlist = const <String>[]}) async {
  final String text = File('fixtures/$name').readAsStringSync();
  final Orchestrator orchestrator = Orchestrator(
    FixtureObservationSource.fromJson(jsonDecode(text) as Map<String, dynamic>),
    userAllowlist: allowlist,
  );
  await orchestrator.scan((_, __, ___) {});
  return orchestrator;
}

void main() {
  group('JSON 报告', () {
    test('含完整 self_check，未覆盖信息可被远程读到', () async {
      final Orchestrator o = await runFixture('clean_machine.json');
      final Map<String, dynamic> j =
          jsonDecode(toJsonReport(o.result, username: kUser, machineName: kMachine))
              as Map<String, dynamic>;

      // Review Focus #1：报告里必须能看出「这次没看到什么」。
      expect(j['self_check']['session0_visible'], 0);
      expect(j['self_check']['elevated'], false);
      expect(j['self_check']['process_total'], 690);
      expect(j['uncovered_count'], greaterThan(0));
      expect(j['schema_version'], kReportSchemaVersion);
      expect(j['duration_ms'], isA<int>());
    });

    test('二期占位字段一期以 null 出现，键存在', () async {
      final Orchestrator o = await runFixture('silverfox_sample.json');
      final Map<String, dynamic> j =
          jsonDecode(toJsonReport(o.result, username: kUser, machineName: kMachine))
              as Map<String, dynamic>;
      final Map<String, dynamic> first =
          (j['findings'] as List<dynamic>).first as Map<String, dynamic>;
      expect(first.containsKey('confidence'), isTrue);
      expect(first['confidence'], isNull);
      expect(first.containsKey('suggested_action'), isTrue);
      expect(first.containsKey('change_record'), isTrue);
    });

    test('用户名与机器名被脱敏，路径其余部分保留', () async {
      final Orchestrator o = await runFixture('silverfox_sample.json');
      final String text = toJsonReport(o.result, username: kUser, machineName: kMachine);
      expect(text, isNot(contains(kUser)));
      expect(text, isNot(contains(kMachine)));
      // 路径本身不能被动过 —— 它是远程判断该不该动手的唯一依据。
      expect(text, contains(r'Documents\\WindowsData\\QduoQFO.exe'));
    });

    test('covered=false 的条目在报告里可被筛出', () async {
      final Orchestrator o = await runFixture('silverfox_sample.json');
      final Map<String, dynamic> j =
          jsonDecode(toJsonReport(o.result, username: kUser, machineName: kMachine))
              as Map<String, dynamic>;
      final List<dynamic> uncovered = (j['findings'] as List<dynamic>)
          .where((dynamic f) => (f as Map<String, dynamic>)['covered'] == false)
          .toList();
      expect(uncovered, isNotEmpty);
    });

    test('白名单折叠的条目仍在报告里被标出，不是消失', () async {
      final Orchestrator o =
          await runFixture('silverfox_sample.json', allowlist: <String>['QduoQFO.exe']);
      final Map<String, dynamic> j =
          jsonDecode(toJsonReport(o.result, username: kUser, machineName: kMachine))
              as Map<String, dynamic>;
      expect(
        (j['findings'] as List<dynamic>)
            .any((dynamic f) => (f as Map<String, dynamic>)['allowlisted'] == true),
        isTrue,
      );
    });
  });

  group('CSV 报告', () {
    test('表头固定且每行列数一致', () async {
      final Orchestrator o = await runFixture('silverfox_sample.json');
      final String csv = toCsvReport(o.result, username: kUser, machineName: kMachine);
      final List<String> lines = csv.split('\r\n').where((String l) => l.isNotEmpty).toList();

      expect(lines.first, kCsvHeader);
      expect(kCsvHeader.split(',').length, 10);
      for (final String line in lines.skip(1)) {
        // 逐行数字段数。含逗号的路径必须已转义，否则这里会 >10。
        expect(_countCsvFields(line), 10, reason: '列数不一致: $line');
      }
    });

    test('locator 里的逗号与双引号按 RFC 4180 转义', () async {
      final Orchestrator o = await runFixture('silverfox_sample.json');
      final String csv = toCsvReport(o.result, username: kUser, machineName: kMachine);

      // TCLService 那条的 display_name 里带双引号，必须被包起来并把内部引号翻倍。
      expect(csv, contains('""'), reason: '内部双引号必须翻倍');
      final List<String> rows =
          csv.split('\r\n').where((String l) => l.isNotEmpty).skip(1).toList();
      expect(rows, isNotEmpty);
      // 转义正确的话，含引号的那一行仍然恰好 10 个字段。
      for (final String row in rows) {
        expect(_countCsvFields(row), 10, reason: '转义后列数必须仍是 10: $row');
      }
    });

    test('同样做脱敏', () async {
      final Orchestrator o = await runFixture('silverfox_sample.json');
      final String csv = toCsvReport(o.result, username: kUser, machineName: kMachine);
      expect(csv, isNot(contains(kUser)));
      expect(csv, isNot(contains(kMachine)));
    });
  });

  group('日志', () {
    test('文件名是 yinhuguard-<ISO>，冒号换成连字符', () {
      final String name = logFileNameFor(DateTime.utc(2026, 10, 14, 12, 0, 0));
      expect(name, 'yinhuguard-2026-10-14T12-00-00.log');
      expect(name, isNot(contains(':')));
    });

    test('写入的内容含自检、各面条数与未覆盖原因', () async {
      final Orchestrator o = await runFixture('clean_machine.json');
      final Directory tmp = Directory.systemTemp.createTempSync('yh_log_test');
      addTearDown(() => tmp.deleteSync(recursive: true));

      final File file =
          await writeScanLog(o.result, tmp, username: kUser, machineName: kMachine);
      expect(file.existsSync(), isTrue);

      final String text = file.readAsStringSync();
      expect(text, contains('== 自检 =='));
      expect(text, contains('Session 0 可见进程: 0'));
      expect(text, contains('== 各扫描面 =='));
      expect(text, contains('processes:'));
      expect(text, contains('UNCOVERED'));
      expect(text, contains('权限不足'));
      // 未提权 + Session 0 全黑时必须写明不能据此判断干净。
      expect(text, contains('不覆盖系统进程'));
      expect(text, isNot(contains(kUser)));
    });
  });

  group('rules.json', () {
    test('不含 vafdska 与 MiniFilterDrv —— 查不到任何银狐出处，不作 IOC', () {
      final Map<String, dynamic> rules =
          jsonDecode(File('rules/rules.json').readAsStringSync()) as Map<String, dynamic>;

      // 断言的是**语义字段**，不是整个文件的文本：文件里有一段说明为什么
      // 不收录这两个名字，那段说明本身当然会提到它们。按文本断言会把
      // 「解释为什么不收录」和「收录了」混为一谈。
      final List<String> forbidden = <String>['vafdska', 'minifilterdrv'];
      for (final String key in <String>[
        'service_interpreter_keywords',
        'process_allowlist',
        'hard_allowlist',
        'system_process_names',
      ]) {
        final Object? value = rules[key];
        if (value is! List) {
          continue;
        }
        for (final Object? entry in value) {
          expect(
            forbidden.contains((entry as String).toLowerCase()),
            isFalse,
            reason: '$key 里出现了 $entry',
          );
        }
      }
      // 确保这几个键都被真的检查过，而不是全被 continue 跳过。
      expect(rules['hard_allowlist'], isA<List<dynamic>>());
      expect(rules['system_process_names'], isA<List<dynamic>>());
    });

    test('六元关键字与两个允许前缀与 spec §8 一致', () {
      final Map<String, dynamic> rules =
          jsonDecode(File('rules/rules.json').readAsStringSync()) as Map<String, dynamic>;
      expect(rules['service_interpreter_keywords'], <String>[
        'cmd /c',
        'powershell',
        'wscript',
        'cscript',
        'mshta',
        'pwsh',
      ]);
      expect(rules['service_path_allow_prefixes'], <String>[
        r'C:\Windows\System32',
        r'C:\Windows\SysWOW64',
      ]);
      expect(rules['hard_allowlist'], contains('swprv'));
      expect(rules['hard_allowlist'],
          contains('MicrosoftSoftware2ShadowCop4yProvider'));
    });
  });
}

/// 数一行 CSV 有多少个字段，尊重双引号包裹与内部翻倍的双引号。
int _countCsvFields(String line) {
  int fields = 1;
  bool inQuotes = false;
  for (int i = 0; i < line.length; i++) {
    final String c = line[i];
    if (c == '"') {
      if (inQuotes && i + 1 < line.length && line[i + 1] == '"') {
        i++; // 翻倍的双引号，跳过第二个
      } else {
        inQuotes = !inQuotes;
      }
    } else if (c == ',' && !inQuotes) {
      fields++;
    }
  }
  return fields;
}
