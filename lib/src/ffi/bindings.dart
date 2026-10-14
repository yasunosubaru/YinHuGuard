// lib/src/ffi/bindings.dart
//
// C ABI 的 Dart 侧映射。字段**顺序即 ABI** —— 顺序错了不会编译报错，
// 只会在运行期把指针当整数读出来，然后报告里出现一堆乱码路径。
// test/bindings_layout_test.dart 把三个结构的尺寸钉死，就是为了让这类错误
// 在编译后立刻暴露，而不是等真机上第一次扫描。
//
// 用 DynamicLibrary.open + lookupFunction 而不是 @Native：后者要求额外的
// 代码生成步骤，而这里只有九个符号要绑。
//
// 三个结构在 x64 上的布局（与 test 里的断言一致）：
//   YhFinding     56 字节 = 3 指针(24) + 5 个 int32(20) 补齐到 48 + double(8)
//   YhFindingList 16 字节 = 指针(8) + size_t(8)
//   YhSelfCheck   24 字节 = 6 个 int32

import 'dart:ffi';

import 'package:ffi/ffi.dart';

/// 与 C 侧 `YhFinding` 逐字段对应。
final class YhFinding extends Struct {
  external Pointer<Utf8> locator;
  external Pointer<Utf8> displayName;
  external Pointer<Utf8> criteria;
  @Int32()
  external int attributesVerified;
  @Int32()
  external int hidden;
  @Int32()
  external int system;
  @Int32()
  external int elevationRequired;
  @Int32()
  external int covered;
  @Double()
  external double timestamp;
}

/// 与 C 侧 `YhFindingList` 对应。count 是 size_t，在 x64 上 8 字节，
/// 用 @UintPtr() 而不是 @Int32() —— 后者会把高位读成相邻内存。
final class YhFindingList extends Struct {
  external Pointer<YhFinding> items;
  @UintPtr()
  external int count;
}

/// 与 C 侧 `YhSelfCheck` 对应。
final class YhSelfCheck extends Struct {
  @Int32()
  external int elevated;
  @Int32()
  external int processTotal;
  @Int32()
  external int processPathResolved;
  @Int32()
  external int session0Visible;
  @Int32()
  external int servicesTotal;
  @Int32()
  external int servicesWithPath;
}

/// 返回码。spec §3.1：0 = 成功，1 = 配置无效，2 = 分配失败。
const int kOk = 0;
const int kConfigInvalid = 1;
const int kAllocFailed = 2;

// ---- 函数签名 -------------------------------------------------------------

typedef _EngineCreateC = Pointer<Void> Function(Pointer<Utf8>);
typedef _EngineCreateDart = Pointer<Void> Function(Pointer<Utf8>);

typedef _EngineDestroyC = Void Function(Pointer<Void>);
typedef _EngineDestroyDart = void Function(Pointer<Void>);

typedef _SelfCheckC = Int32 Function(Pointer<Void>, Pointer<YhSelfCheck>);
typedef _SelfCheckDart = int Function(Pointer<Void>, Pointer<YhSelfCheck>);

typedef _ScanC = Int32 Function(Pointer<Void>, Pointer<YhFindingList>);
typedef _ScanDart = int Function(Pointer<Void>, Pointer<YhFindingList>);

typedef _LastErrorC = Pointer<Utf8> Function();
typedef _LastErrorDart = Pointer<Utf8> Function();

typedef _FindingListFreeC = Void Function(Pointer<YhFindingList>);
typedef _FindingListFreeDart = void Function(Pointer<YhFindingList>);

typedef _StringFreeC = Void Function(Pointer<Utf8>);
typedef _StringFreeDart = void Function(Pointer<Utf8>);

/// 已解析好的九个符号。一次 open 只建一次。
class EngineBindings {
  /// 持有 DynamicLibrary 引用是**必须的**，不是冗余：函数指针指向它的代码段，
  /// 一旦这里不再引用而被卸载，之后调用那些函数指针就是野指针。
  final DynamicLibrary library;

  final _EngineCreateDart engineCreate;
  final _EngineDestroyDart engineDestroy;
  final _SelfCheckDart selfCheck;
  final _ScanDart scanProcesses;
  final _ScanDart scanRunKeys;
  final _ScanDart scanServices;
  final _LastErrorDart lastError;
  final _FindingListFreeDart findingListFree;
  final _StringFreeDart stringFree;

  EngineBindings._(
    this.library,
    this.engineCreate,
    this.engineDestroy,
    this.selfCheck,
    this.scanProcesses,
    this.scanRunKeys,
    this.scanServices,
    this.lastError,
    this.findingListFree,
    this.stringFree,
  );

  /// 打开引擎 DLL。九个符号缺任何一个都直接抛 —— 缺符号说明 DLL 版本不对，
  /// 继续跑下去只会得到「什么都扫不到」这个最坏的假象。
  factory EngineBindings.open(String dllPath) {
    final DynamicLibrary library = DynamicLibrary.open(dllPath);
    return EngineBindings._(
      library,
      library.lookupFunction<_EngineCreateC, _EngineCreateDart>('yh_engine_create'),
      library.lookupFunction<_EngineDestroyC, _EngineDestroyDart>('yh_engine_destroy'),
      library.lookupFunction<_SelfCheckC, _SelfCheckDart>('yh_self_check'),
      library.lookupFunction<_ScanC, _ScanDart>('yh_scan_processes'),
      library.lookupFunction<_ScanC, _ScanDart>('yh_scan_run_keys'),
      library.lookupFunction<_ScanC, _ScanDart>('yh_scan_services'),
      library.lookupFunction<_LastErrorC, _LastErrorDart>('yh_last_error'),
      library.lookupFunction<_FindingListFreeC, _FindingListFreeDart>('yh_finding_list_free'),
      library.lookupFunction<_StringFreeC, _StringFreeDart>('yh_string_free'),
    );
  }

  /// 读最近的错误文本。返回的是引擎拥有的内存，调用方不要释放。
  String readLastError() => lastError().toDartString();
}
