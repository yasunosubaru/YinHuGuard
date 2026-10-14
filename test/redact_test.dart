import 'package:test/test.dart';
import 'package:yinhuguard_core/src/criteria/redact.dart';

void main() {
  group('redactPath', () {
    test('用户名替换为 <USER>，机器名替换为 <MACHINE>', () {
      expect(
        redactPath(
          r'C:\Users\zhangwei\AppData\Local\a.exe',
          username: 'zhangwei',
          machineName: 'TEST-PC',
        ),
        r'C:\Users\<USER>\AppData\Local\a.exe',
      );
    });

    test('机器名出现在路径任意位置都被替换', () {
      expect(
        redactPath(
          r'\\TEST-PC\share\a.exe',
          username: 'zhangwei',
          machineName: 'TEST-PC',
        ),
        r'\\<MACHINE>\share\a.exe',
      );
    });

    test('用户名与机器名同时出现时都被替换', () {
      expect(
        redactPath(
          r'\\PC\Users\zhangwei\a.exe',
          username: 'zhangwei',
          machineName: 'PC',
        ),
        r'\\<MACHINE>\Users\<USER>\a.exe',
      );
    });

    test('路径其余部分原样保留 —— 不脱敏路径是 spec §9.1 的硬要求', () {
      // 「这文件到底在哪」是远程判断该不该动手的唯一依据，一个字符都不能动。
      const String path = r'C:\Program Files\Internet Explorer\Ab3xY9\QduoQFO.exe';
      expect(
        redactPath(path, username: 'zhangwei', machineName: 'PC'),
        path,
      );
    });

    test('空格、大小写、8.3 短名都不规范化', () {
      // 注意机器名与用户名不能是路径的子串，否则会命中的是子串本身而不是这台机器
      // —— 那是夹具的问题，不是脱敏器的问题（子串替换就是这个语义）。
      const String path = r'C:\PROGRA~1\My App\aExe.EXE';
      expect(
        redactPath(path, username: 'user01', machineName: 'PC-01'),
        path,
      );
    });

    test('大小写不敏感替换', () {
      expect(
        redactPath(
          r'C:\Users\ZhangWei\a.exe',
          username: 'zhangwei',
          machineName: 'PC',
        ),
        r'C:\Users\<USER>\a.exe',
      );
    });

    test('空用户名或机器名时跳过该项，不产生空占位符', () {
      // 空串会匹配任何位置，把整条路径切碎 —— 必须跳过。
      expect(
        redactPath(r'C:\a\b.exe', username: '', machineName: ''),
        r'C:\a\b.exe',
      );
      expect(
        redactPath(r'C:\Users\zhangwei\b.exe', username: '', machineName: ''),
        r'C:\Users\zhangwei\b.exe',
      );
    });

    test('只有机器名时不误伤其它内容', () {
      expect(
        redactPath(r'C:\a\b.exe', username: '', machineName: 'b.exe'),
        r'C:\a\<MACHINE>',
      );
    });

    test('用户名含正则元字符时按字面匹配', () {
      // 用户名里带 . 或 + 并不合法，但脱敏器不该因此改变行为 —— 用 RegExp.escape。
      expect(
        redactPath(r'C:\Users\a.b\c.exe', username: 'a.b', machineName: ''),
        r'C:\Users\<USER>\c.exe',
      );
    });

    test('中文与空格路径原样保留', () {
      const String path = r'C:\Windows\Temp\临时 目录\文件.exe';
      expect(
        redactPath(path, username: 'zhangwei', machineName: 'PC'),
        path,
      );
    });
  });
}
