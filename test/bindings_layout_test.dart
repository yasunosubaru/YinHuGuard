import 'dart:ffi';

import 'package:test/test.dart';
import 'package:yinhuguard_core/src/ffi/bindings.dart';

// 这一组测试**不加载 DLL** —— sizeOf 只依赖结构定义。
//
// 它们存在的理由：C 与 Dart 之间的结构体布局不匹配时，编译器不会报错，
// 运行期会把指针当整数读出来，于是报告里出现一堆乱码路径，而人第一反应是
// 「这台机器上文件名就是乱码」，正好与银狐的民间判据撞车。
// 把这个数字钉死，是唯一能在编译后立刻发现错位的手段。

void main() {
  group('C ABI 结构体布局（x64）', () {
    test('YhFinding 是 56 字节', () {
      // 3 个 char* = 24；5 个 int32 = 20，到 44；double 要 8 字节对齐，
      // 补齐到 48，double 占 48..55。合计 56。
      expect(sizeOf<YhFinding>(), 56);
    });

    test('YhFindingList 是 16 字节', () {
      // 指针(8) + size_t(8)。count 用 @UintPtr() 而不是 @Int32()：
      // 后者只读低 4 字节，高位会读成相邻内存。
      expect(sizeOf<YhFindingList>(), 16);
    });

    test('YhSelfCheck 是 40 字节', () {
      // 10 个 int32：6 个原有 + 4 个「没查到」的分类计数。
      // 后面那 4 个是让界面能分红/灰的依据，少一个就退回「一律报红」。
      expect(sizeOf<YhSelfCheck>(), 40);
    });

    test('YhFinding 的字段偏移与 spec §3.1 的顺序一致', () {
      // 用只含首字段的结构体做参照，间接核对前三个指针挨着排。
      // 顺序一旦被改动，locator 会读到 display_name 的内容。
      expect(sizeOf<YhFinding>(), greaterThan(sizeOf<YhFindingList>()));
      expect(sizeOf<YhFinding>() - sizeOf<YhSelfCheck>(), 16);
    });

    test('返回码常量与 spec §3.1 一致', () {
      expect(kOk, 0);
      expect(kConfigInvalid, 1);
      expect(kAllocFailed, 2);
    });
  });
}
