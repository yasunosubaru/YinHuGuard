// app/lib/elevate.dart
//
// 提权重启入口。
//
// 走 ShellExecuteExW + "runas"（Windows 官方的提权入口），**不用**
// Start-Process / powershell 包装 —— 一个查杀远控木马的工具去 spawn
// PowerShell，正是它自己要清理的那类行为，会被杀软优先针对（spec 硬约束 1）。
//
// 用户取消 UAC 是**正常路径**，不是错误：取消后必须保持「系统进程未覆盖」的
// 提示，不能因为提权没成功就把结论改成看起来完整。

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// 重扫描时原样保留 --fixture / --config / --dll，其余参数透传。
/// 不追加已有的 --relaunched，避免连续弹 UAC。
List<String> buildRelaunchArgs(List<String> argv) {
  final List<String> out = <String>[];
  for (int i = 0; i < argv.length; i++) {
    final String arg = argv[i];
    if (arg == '--relaunched') {
      continue;
    }
    out.add(arg);
    // 这三个旗标带值，值必须跟着一起搬。
    if (arg == '--fixture' || arg == '--config' || arg == '--dll') {
      if (i + 1 < argv.length) {
        out.add(argv[i + 1]);
        i++;
      }
    }
  }
  out.add('--relaunched');
  return out;
}

/// 本次是否已经带过 --relaunched。带过而仍未提权，说明用户取消了 UAC，
/// 此时按钮应当禁用并说明原因，而不是继续可点。
bool alreadyRelaunched(List<String> argv) => argv.contains('--relaunched');

// ---- Win32 ----------------------------------------------------------------

typedef _GetCurrentProcessC = IntPtr Function();
typedef _GetCurrentProcessDart = int Function();

typedef _OpenProcessTokenC = Int32 Function(IntPtr, Uint32, Pointer<IntPtr>);
typedef _OpenProcessTokenDart = int Function(int, int, Pointer<IntPtr>);

typedef _GetTokenInformationC = Int32 Function(
    IntPtr, Int32, Pointer<Void>, Uint32, Pointer<Uint32>);
typedef _GetTokenInformationDart = int Function(
    int, int, Pointer<Void>, int, Pointer<Uint32>);

typedef _CloseHandleC = Int32 Function(IntPtr);
typedef _CloseHandleDart = int Function(int);

typedef _GetLastErrorC = Uint32 Function();
typedef _GetLastErrorDart = int Function();

typedef _ShellExecuteExC = Int32 Function(Pointer<ShellExecuteInfo>);
typedef _ShellExecuteExDart = int Function(Pointer<ShellExecuteInfo>);

const int _tokenQuery = 0x0008;
const int _tokenElevation = 20;

const int _seeMaskNoCloseProcess = 0x00000040;
const int _seeMaskNoAsync = 0x00000100;
const int _swShowNormal = 1;
const int _errorCancelled = 1223;

/// SHELLEXECUTEINFOW。x64 布局（字段偏移）：
///   cbSize 0 / fMask 4 / hwnd 8 / lpVerb 16 / lpFile 24 / lpParameters 32
///   lpDirectory 40 / nShow 48 (补齐到 56) / hInstApp 56 / lpIDList 64
///   lpClass 72 / hkeyClass 80 / dwHotKey 88 / hIcon|hMonitor 96 / hProcess 104
/// 合计 112 字节。偏移错一个字段，调用的就是别的动词或别的文件，
/// 而 Windows 只会返回一个泛泛的失败，所以 test/elevate_args_test.dart
/// 把尺寸钉死。
///
/// 句柄字段必须写成 `@IntPtr() external int`：dart:ffi 不允许 Struct 的字段
/// 声明为 IntPtr 类型，只能用注解把宽度钉住。
final class ShellExecuteInfo extends Struct {
  @Uint32()
  external int cbSize;
  @Uint32()
  external int fMask;
  @IntPtr()
  external int hwnd;
  external Pointer<Utf16> lpVerb;
  external Pointer<Utf16> lpFile;
  external Pointer<Utf16> lpParameters;
  external Pointer<Utf16> lpDirectory;
  @Int32()
  external int nShow;
  @IntPtr()
  external int hInstApp;
  external Pointer<Void> lpIDList;
  external Pointer<Utf16> lpClass;
  @IntPtr()
  external int hkeyClass;
  @Uint32()
  external int dwHotKey;
  @IntPtr()
  external int hIconOrMonitor;
  @IntPtr()
  external int hProcess;
}

class _Api {
  final DynamicLibrary _lib = DynamicLibrary.open('kernel32.dll');
  final DynamicLibrary _shell32 = DynamicLibrary.open('shell32.dll');

  late final _GetCurrentProcessDart getCurrentProcess =
      _lib.lookupFunction<_GetCurrentProcessC, _GetCurrentProcessDart>(
          'GetCurrentProcess');
  late final _OpenProcessTokenDart openProcessToken =
      _lib.lookupFunction<_OpenProcessTokenC, _OpenProcessTokenDart>(
          'OpenProcessToken');
  late final _GetTokenInformationDart getTokenInformation =
      _lib.lookupFunction<_GetTokenInformationC, _GetTokenInformationDart>(
          'GetTokenInformation');
  late final _CloseHandleDart closeHandle =
      _lib.lookupFunction<_CloseHandleC, _CloseHandleDart>('CloseHandle');
  late final _GetLastErrorDart getLastError =
      _lib.lookupFunction<_GetLastErrorC, _GetLastErrorDart>('GetLastError');
  late final _ShellExecuteExDart shellExecuteEx =
      _shell32.lookupFunction<_ShellExecuteExC, _ShellExecuteExDart>(
          'ShellExecuteExW');
}

_Api? _api;
_Api get _apiInstance => _api ??= _Api();

/// 当前进程是否已提权。
bool isElevated() {
  final _Api api = _apiInstance;
  final Pointer<IntPtr> token = calloc<IntPtr>();
  try {
    if (api.openProcessToken(api.getCurrentProcess(), _tokenQuery, token) == 0) {
      return false;  // 问不出来就按未提权处理：宁可少报权限，不可多报
    }
    final Pointer<Int32> elevated = calloc<Int32>();
    final Pointer<Uint32> returned = calloc<Uint32>();
    try {
      // TOKEN_ELEVATION 就是一个 int32
      final int ok = api.getTokenInformation(
          token.value, _tokenElevation, elevated.cast<Void>(), 4, returned);
      return ok != 0 && elevated.value != 0;
    } finally {
      calloc.free(elevated);
      calloc.free(returned);
    }
  } finally {
    if (token.value != 0) {
      api.closeHandle(token.value);
    }
    calloc.free(token);
  }
}

enum ElevateResult {
  /// 新实例已拉起（当前实例应立刻退出，把窗口让给它）。
  launched,

  /// 用户在 UAC 对话框上点了「否」。正常路径。
  cancelled,

  /// 其它失败，[relaunchElevated] 的返回字符串里有错误码。
  failed,
}

ElevateResult relaunchElevated(List<String> args, {required String exePath}) {
  final _Api api = _apiInstance;
  final List<String> relaunchArgs = buildRelaunchArgs(args);

  final Pointer<ShellExecuteInfo> info = calloc<ShellExecuteInfo>();
  final Pointer<Utf16> verb = 'runas'.toNativeUtf16();
  final Pointer<Utf16> file = exePath.toNativeUtf16();
  final Pointer<Utf16> params = relaunchArgs.join(' ').toNativeUtf16();
  final Pointer<Utf16> dir = File(exePath).parent.path.toNativeUtf16();

  try {
    info.ref
      ..cbSize = sizeOf<ShellExecuteInfo>()
      ..fMask = _seeMaskNoCloseProcess | _seeMaskNoAsync
      ..hwnd = 0
      ..lpVerb = verb
      ..lpFile = file
      ..lpParameters = params
      ..lpDirectory = dir
      ..nShow = _swShowNormal;

    final int ok = api.shellExecuteEx(info);
    if (ok != 0) {
      // 新实例已经起来，不必等它；当前实例该退出。
      if (info.ref.hProcess != 0) {
        api.closeHandle(info.ref.hProcess);
      }
      return ElevateResult.launched;
    }
    if (api.getLastError() == _errorCancelled) {
      return ElevateResult.cancelled;
    }
    return ElevateResult.failed;
  } finally {
    calloc.free(info);
    calloc.free(verb);
    calloc.free(file);
    calloc.free(params);
    calloc.free(dir);
  }
}
