// app/lib/cli.dart
//
// 命令行模式。存在的理由：报告可能要在没有桌面环境的机器上取证，
// 也方便把结果喂给下一段脚本。
//
// 一个与 plan 不一致的裁定，写在这里免得被当 bug 改回去：
// **无参数 = 启动图形界面，不是跑扫描。** plan 里写过「无参等价 --scan」，
// 那会让用户双击 exe 时弹出一个黑框跑完全机扫描 —— 对一个查杀工具来说，
// 那是它最像恶意软件的样子。无参必须进 GUI。
//
// 退出码（供脚本判断，不表示好坏，只表示状态）：
//   0  扫描完成，没有命中
//   10 扫描完成，有命中
//   1  参数错误
//   2  引擎错误（配置无效或分配失败）
//   3  找不到配置文件/引擎

import 'dart:ffi';
import 'dart:io';

sealed class CliAction {
  const CliAction();
}

/// 启动图形界面（无参数，或只带了 --fixture/--config/--dll 这类修饰）。
class RunGui extends CliAction {
  const RunGui();
}

/// 跑一次扫描并把结果写到 [jsonOutPath]（null 表示只写默认位置）。
class RunScan extends CliAction {
  final String? jsonOutPath;
  const RunScan({this.jsonOutPath});
}

class InvalidArgs extends CliAction {
  final String message;
  const InvalidArgs(this.message);
}

/// 带值的修饰旗标。它们不决定模式，只影响路径解析。
const Set<String> kValueFlags = <String>{'--fixture', '--config', '--dll'};

CliAction parseArgs(List<String> args) {
  String? jsonOut;
  bool wantScan = false;

  for (int i = 0; i < args.length; i++) {
    final String arg = args[i];

    if (kValueFlags.contains(arg)) {
      // 值必须跟着；缺值就是参数拼错了，不能猜。
      if (i + 1 >= args.length) {
        return InvalidArgs('$arg 后面缺少路径');
      }
      i++; // 跳过值
      continue;
    }

    if (arg == '--relaunched') {
      continue; // 提权重启标记，此处无意义
    }

    if (arg == '--scan') {
      wantScan = true;
      continue;
    }

    if (arg == '--json') {
      if (i + 1 >= args.length) {
        return const InvalidArgs('--json 后面缺少输出路径');
      }
      jsonOut = args[i + 1];
      i++;
      wantScan = true;
      continue;
    }

    return InvalidArgs('无法识别的参数：$arg');
  }

  if (!wantScan) {
    // 无参数，或只带了路径修饰 —— 都是要开界面。
    return const RunGui();
  }
  return RunScan(jsonOutPath: jsonOut);
}

/// 控制台输出。
///
/// Flutter 的 Windows 产物是 GUI 子系统程序，默认没有控制台：直接 print
/// 会被丢掉。标准做法是先 AttachConsole(ATTACH_PARENT_PROCESS) 挂上父进程的
/// 控制台，之后 stdout 才指向它。
///
/// 刻意**不**写 `\\.\CONOUT$`：没有已附加控制台时打开该设备会阻塞，
/// 一个查询工具卡死在输出这一步比看不到输出糟糕得多。挂不上就算了 ——
/// 报告已经落盘，控制台看不到只是不方便。
Future<void> writeToConsole(String text) async {
  await _attachParentConsole();
  try {
    stdout.write(text);
  } catch (_) {
    // GPU 子系统下 stdout 不可用是常态，不报错。
  }
}

bool _consoleAttached = false;

Future<void> _attachParentConsole() async {
  if (_consoleAttached) {
    return;
  }
  _consoleAttached = true;
  try {
    final DynamicLibrary kernel32 = DynamicLibrary.open('kernel32.dll');
    final int Function(int) attach =
        kernel32.lookupFunction<Int32 Function(Uint32), int Function(int)>(
            'AttachConsole');
    attach(0xFFFFFFFF); // ATTACH_PARENT_PROCESS
  } catch (_) {
    // 忽略
  }
}
