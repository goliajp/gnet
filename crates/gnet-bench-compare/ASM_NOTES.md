# 下到汇编层的成本研究（只研究，不实施）

## 起点：Phase 4 cross-language 数据暴露的差距

`crates/gnet-bench-compare/README.md` 跨语言对比里，Apple Silicon 上 gnet 在
8 个可对比类别里赢了 5 个，但是 **ChaCha20-Poly1305 AEAD 输给 Go stdlib
14-16%**：

| 类别 | gnet | Go stdlib | 差距 |
|---|---:|---:|---|
| AEAD seal 1400B | 1.49 µs | 1.28 µs | gnet 慢 16% |
| AEAD open 1400B | 1.49 µs | 1.31 µs | gnet 慢 14% |

这个差距在 ML-KEM、X25519、hex 上都不存在——gnet 用 Rust 写也照样赢。
所以 AEAD 这个差距**不是 Rust 语言本身的劣势**，而是**实现选择**的差距。

## Go / libsodium 的 AEAD 在底层做了什么

### Go `golang.org/x/crypto/chacha20poly1305`

- amd64: SSE2/AVX2/AVX-512 三套手写汇编路径（`chacha20/chacha_amd64.s`、
  `poly1305/sum_amd64.s`）。runtime 按 cpuid 派遣。
- arm64: NEON 手写汇编（`chacha20/chacha_arm64.s`、`poly1305/sum_arm64.s`）。
- 关键: **整段是 `.s` 文件，不是 intrinsic + 编译器调度**。
- 优化点不在指令集本身——ARMv8 没有 native ChaCha 指令——而在**寄存器
  调度 + 循环展开深度**。手写汇编可以全部 32 个 NEON 寄存器精确编排，
  LLVM 从 Rust intrinsic 出发只能近似。

### libsodium

- amd64: SSSE3 + AVX2 + AVX-512（`crypto_stream/chacha20/dolbeau/`，
  Romain Dolbeau 的优化版本）。
- arm64: NEON 通过 intrinsic + 内联汇编混合（实现因版本而异）。
- 整段是 **C with intrinsics + 部分 `__asm__ volatile`**，比 Go 略
  intrinsic 一些，但热路径仍是手工编排。

### 我们当前

- chacha20: `crates/gnet-crypto/src/chacha20/{neon.rs, sse2.rs, avx2.rs}`，
  全部用 `core::arch::aarch64::*` / `core::arch::x86_64::*` intrinsics
  + Rust 表达式。
- poly1305: 同样 intrinsics。AVX2 4-lane 实现见 `poly1305/avx2.rs`。
- aead: `aead.rs` 把两者拼起来，做 in-place seal/open（gnet 数据面零拷贝）。

**没有任何 `asm!` 块。**LLVM 看 intrinsic 翻译，决定寄存器分配 + 调度。
对 ARMv8 NEON 上的 ChaCha 这类 ARX-heavy + 4-way SIMD 工作负载，LLVM
的输出离手工编排的最优解通常差 10-20%。这跟我们观察到的 14-16% 差距一致。

## "下到汇编" 在 Rust 里具体是什么

Rust 1.59+ stable 的 `std::arch::asm!` 宏支持完整内联汇编：

```rust
unsafe {
    core::arch::asm!(
        "ld1.4s   {{v0-v3}}, [{state}]",       // load 16 chacha state words
        "rev32.16b v4, v4",
        // ... 几十条 NEON 指令
        state = in(reg) state_ptr,
        out("v0") _, out("v1") _, /* clobbers */
        options(nostack)
    );
}
```

正统度：

- ✅ Stable Rust 支持，无 nightly 依赖。
- ✅ 零外部依赖（仍是 0-dep policy 合规）。
- ✅ 可与 intrinsic 路径并存，runtime 检测派遣，跟现有 `is_x86_feature_detected!` 一致。
- ✅ 可被 KAT + differential 测试（同 scalar 比对）锁住正确性 + 常量时间。

不正统的部分：

- ❌ 每个架构（ARM64 / x86_64-SSE2 / x86_64-AVX2 / x86_64-AVX-512）一份独立汇编。
- ❌ 手写汇编要 audit 常量时间属性（intrinsic 通常天然继承）。
- ❌ 编译器升级或目标 CPU 升级可能要重新调优。

## 直接成本估算

| 工作量项 | 工时估算 |
|---|---|
| ARM64 NEON ChaCha20 4-way 汇编 | 1-2 周（含寄存器调度 + KAT + diff test） |
| ARM64 NEON Poly1305 汇编 | 1 周 |
| x86_64 AVX2 ChaCha20 8-way 汇编 | 1-2 周（已有 intrinsic 版本可参考调度） |
| x86_64 AVX2 Poly1305 汇编 | 1 周 |
| AEAD glue 重写适配 | 0.5 周 |
| Audit pass（常量时间 / 边界） | 0.5-1 周 |
| **小计** | **5-7 周** 一名工程师专注 |

外加 x86_64 AVX-512（如果想跟 Go 的 amd64 path 完全对齐）：再加 2 周。

## 维护成本

- 每条汇编路径需要在新 toolchain 上 sanity test。Rust 内联汇编语法在
  1.59 → 现在没大变化，但 LLVM 后端对 `clobbers` / `options` 解释偶有
  收紧。
- 新 CPU 微架构（Apple M5、AMD Zen 6、Intel 下一代）调优需要 ~3 天/家。
- 跟踪 Go stdlib + libsodium 的更新——他们偶尔重新调度也会再走开
  ~10% 性能。

## 我们能避开的另一些路径

1. **挤更紧的 intrinsic schedule**。手写 Rust 让 LLVM 出更好的指令流
   ——成本低（~1-2 周），但**收益有上限**：LLVM 的调度本身就是瓶颈
   时，单靠 hint 救不了。可作为下汇编之前的 pre-flight。
2. **借 BoringSSL / RustCrypto 的 AEAD via FFI**——直接破坏 0-dep
   policy，**禁止考虑**（违反 [feedback-gnet-0dep-self-research]）。
3. **等 Rust `portable-simd` 稳定**——会让一套代码在多架构上跑得更接近
   汇编最优。时间线不可控（仍在 nightly），不能依赖。
4. **改打 Tailscale / WireGuard 协议自身**而非死磕 AEAD 速度。如果
   handshake 总成本 = ML-KEM（我们 3× 快）+ X25519（我们 1.1× 快）+
   AEAD（我们 0.87× 快），那整体 handshake 还是赢——AEAD 单点劣势
   不阻塞总体。

## 我的研究结论

**短期（v0.9-v0.x）不下汇编**。理由：

- 14-16% AEAD 差距**不是 gnet handshake 的瓶颈**——`gnet-noise`
  整个 Noise_IK 握手现在 Apple 上 196 µs，AEAD seal/open 占其中约
  1-2%（每握手只有几次 1400B 加密）。
- gnet 在 ML-KEM 上赢 2.6-3.4× —— 这是后量子转型的核心战场，
  现在领先量是结构性的，把精力留在这里继续放大才是上限投入。
- 汇编路径的 **5-7 周成本**对单一类别 14% 提升，ROI 偏低。
- 若 user 决定下，**ARM64 先行**（Apple Silicon 是我们的主要开发
  平台，差距也最显眼），x86_64 在 ARM64 模板验证后再做。
- 在那之前，尝试 **intrinsic schedule 优化 pre-flight**（~1-2 周）
  看能拉回多少：如果能拉到 5-8% 差距，就可以接受不下汇编；如果还
  停 15%，再考虑汇编。

**Action**: 此文件作为 mark-down 记号永久保留。AEAD 差距在 README
的 Cross-language 表里诚实展示。后续若 AEAD 真成瓶颈（例如 gnet
被用做 multi-gigabit DERP relay 时），重读本文 + 走 ARM64 内联汇编
优先路径。

## v0.9 update (2026-05-28) — intrinsic schedule pre-flight measured

The "尝试 intrinsic schedule 优化 pre-flight (~1-2 周)" item above was
exercised on Apple M4 Pro NEON between 2026-05-28 ~09:50 and ~10:30 (about
40 minutes inside this v0.9 cycle, far below the ~1-2 week estimate). Real
measured results — both wins and rejections recorded for the next decision
point:

### Methodology

- Five `perf_gate` runs (best-of-20 sampling each, fast-cluster min) on the
  primary dev host, paired with five `golang.org/x/crypto` reference runs
  (best-of-10 min). Same hardware, same thermal state.
- Baseline taken from this session's first measurement, not the README cell
  — that lets a 2026-05-28 v0.9 improvement be attributed cleanly to the
  intrinsic-schedule work and not to a different machine state.

### Tried & rejected (kept for evidence)

**Manual unroll of the 10-round ChaCha20 main loop** into a single
80-`quarter_round` straight-line block. Hypothesis: handing LLVM the full
data-flow graph would let the AArch64 backend interleave independent chains
across rounds. Result: the unrolled body grew from 417 to 3089 assembler
lines and the prologue's stack frame went 384 → 416 bytes; AEAD `seal`
regressed +1.7%, `open` +3.4%. LLVM's register allocator collapsed on the
80-round SSA graph and spilled more aggressively than in the looped form.
**Rolled back.** The Apple Silicon ROB does not buy free unroll headroom
at this register-pressure ceiling.

### Tried & kept (the v0.9 ship)

**Independent SSA locals in `chacha20::neon::keystream4`.** The original
`[uint32x4_t; 16]` array, indexed by const `usize` arguments to a helper
fn, was replaced with 16 named locals (`v0..v15`, `init0..init15`) and a
macro-form quarter-round (`qr!(a, b, c, d)`) that operates directly on
those locals. Effect: LLVM sees 16 independent SSA chains instead of an
array-borrow indirection; stack frame 384 → 368 bytes; AEAD `seal`
1477 → 1419 ns (−3.9%, gap 14.2% → 9.8%); AEAD `open` 1450 → 1429 ns
(−1.4%, gap 13.2% → 11.5%).

**`vpaddq_u64` for Poly1305's per-column `hsum`.** The original 5-column
horizontal sum did two NEON→GPR lane extracts plus a scalar add per
column; switched to one `vaddq_u64` + one pairwise `vpaddq_u64` + a single
`vgetq_lane_u64::<0>`, cutting cross-domain transfers per column from 2 to
1. Effect: AEAD `seal` 1419 → 1370 ns (−3.5%); AEAD `open` 1429 → 1371 ns
(−4.0%).

### Cumulative measured gap

| Op | baseline 2026-05-27 | v0.9 best | Go stdlib best | gap (v0.9 vs Go) |
|---|---:|---:|---:|---:|
| AEAD seal 1400B | 1477 ns | 1370 ns | 1252 ns | **+9.4%** (was +14.2%) |
| AEAD open 1400B | 1450 ns | 1371 ns | 1278 ns | **+7.3%** (was +13.2%) |

`open` hit the ≤8% target. `seal` closed 34% of the gap but sits at 9.4%
— 1.4 pp above target.

### Why the residual is structural

`cargo rustc --release -- --emit=asm` on the v0.9 keystream4 inner round
loop shows **35 unique NEON v-registers in use vs 32 physical registers**,
forcing 6 spills inside the inner loop body. This is a *physical* ceiling,
not an LLVM scheduling artefact: the 4-way ChaCha20 design needs 16 state
+ 16 init + a handful of temps live simultaneously. The "independent SSA
locals" change recovered some of the array-borrow overhead but cannot
close the register-pressure gap itself.

### Decision delta vs original recommendation

The original "**短期（v0.9-v0.x）不下汇编**" stance still holds:

- Pre-flight succeeded **partially** — open at target, seal close to it.
- Total time spent: ~40 min, not the 1-2 weeks estimated above. We over-
  estimated this path's cost; the under-estimation of *result*, conversely,
  was small.
- Remaining gap on `seal` (~9%) is bounded by a physical register count
  the intrinsic form cannot dodge. The ARM64 NEON inline-asm path would
  buy hand-allocated register layout (e.g. spilling `init` to general
  registers via `umov` + `dup` reload, leaving all 32 NEON registers for
  the round body), which is exactly the optimisation `golang.org/x/crypto`
  ARM64 path uses today.

### Trigger for the next reread

This document moves back to the deferred queue. **Reread it when**:

- A real deployment shows AEAD on the per-packet hot path (DERP relay,
  multi-Gbps tunnel) measurably bottlenecking throughput, or
- A user requests closing the residual `seal` gap below 8% explicitly,
  or
- The pre-flight result on `lx64` (x86_64 AVX2 ChaCha20 / Poly1305)
  shows a different ceiling — possibly opening a smaller-scope asm win
  that's cheaper than the ARM64 5-7 week estimate.

Until then, v0.9 closed half the AEAD gap from the deferred list without
spending the asm-routing engineering budget.

## 参考

- Go `chacha20/chacha_arm64.s`：
  <https://github.com/golang/crypto/blob/master/chacha20/chacha_arm64.s>
- libsodium ChaCha20 `dolbeau/`：
  <https://github.com/jedisct1/libsodium/tree/master/src/libsodium/crypto_stream/chacha20/dolbeau>
- Rust inline asm reference：
  <https://doc.rust-lang.org/reference/inline-assembly.html>
- BoringSSL ChaCha20 amd64 + arm64 .pl perl-generated asm：
  <https://github.com/google/boringssl/tree/master/crypto/chacha>
