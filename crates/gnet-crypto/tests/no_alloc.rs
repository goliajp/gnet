//! Allocation gate for the data-plane hot path. The per-packet AEAD throughput
//! in BUDGETS.md depends on doing zero heap allocation per packet; this test
//! installs a counting global allocator and asserts the in-place seal/open path
//! allocates nothing, so a future change that quietly adds a per-packet alloc
//! is caught immediately.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use gnet_crypto::aead;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: forwards every call to the system allocator unchanged, only bumping
// a counter on allocation — same soundness as `System` itself.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

#[test]
fn aead_in_place_does_not_allocate_per_packet() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = [0u8; 16];
    let mut pkt = vec![0u8; 1400]; // the only allocation, before we start counting

    // warm any one-time lazy init off the measured window
    let tag = aead::seal_in_place(&key, &nonce, &aad, &mut pkt);
    aead::open_in_place(&key, &nonce, &aad, &mut pkt, &tag).unwrap();

    let before = ALLOCS.load(Ordering::Relaxed);
    for _ in 0..10_000 {
        let tag = aead::seal_in_place(&key, &nonce, &aad, &mut pkt);
        aead::open_in_place(&key, &nonce, &aad, &mut pkt, &tag).unwrap();
    }
    let allocs = ALLOCS.load(Ordering::Relaxed) - before;

    assert_eq!(allocs, 0, "data-plane AEAD must not allocate per packet");
}
