; ModuleID = 'probe4.33a4217a5fa37559-cgu.0'
source_filename = "probe4.33a4217a5fa37559-cgu.0"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@alloc_fd5504b70eb3e20b00fd422ae581440f = private unnamed_addr constant <{ [75 x i8] }> <{ [75 x i8] c"/rustc/2f8d81f9dbac6b8df982199f69da04a4c8357227/library/core/src/num/mod.rs" }>, align 1
@alloc_66139b6f6148a7bd8b23dbb4599e8ac3 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_fd5504b70eb3e20b00fd422ae581440f, [16 x i8] c"K\00\00\00\00\00\00\00y\04\00\00\05\00\00\00" }>, align 8
@str.0 = internal unnamed_addr constant [25 x i8] c"attempt to divide by zero"

; probe4::probe
; Function Attrs: nonlazybind uwtable
define void @_ZN6probe45probe17h167000fa00dc939eE() unnamed_addr #0 {
start:
  %0 = call i1 @llvm.expect.i1(i1 false, i1 false)
  br i1 %0, label %panic.i, label %"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17hf848de710fadaca7E.exit"

panic.i:                                          ; preds = %start
; call core::panicking::panic
  call void @_ZN4core9panicking5panic17h46cee0460b5e3e02E(ptr align 1 @str.0, i64 25, ptr align 8 @alloc_66139b6f6148a7bd8b23dbb4599e8ac3) #3
  unreachable

"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17hf848de710fadaca7E.exit": ; preds = %start
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(none)
declare i1 @llvm.expect.i1(i1, i1) #1

; core::panicking::panic
; Function Attrs: cold noinline noreturn nonlazybind uwtable
declare void @_ZN4core9panicking5panic17h46cee0460b5e3e02E(ptr align 1, i64, ptr align 8) unnamed_addr #2

attributes #0 = { nonlazybind uwtable "probe-stack"="inline-asm" "target-cpu"="x86-64" }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(none) }
attributes #2 = { cold noinline noreturn nonlazybind uwtable "probe-stack"="inline-asm" "target-cpu"="x86-64" }
attributes #3 = { noreturn }

!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{i32 2, !"RtLibUseGOT", i32 1}
!2 = !{!"rustc version 1.76.0-nightly (2f8d81f9d 2023-11-21)"}
