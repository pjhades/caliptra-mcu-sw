// Licensed under the Apache-2.0 license

use crate::riscv::{HEAP, HEAP_SIZE};
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_console::Console;
use caliptra_mcu_libtock_platform::{ErrorCode, Syscalls};
use caliptra_mcu_libtockasync::TockSubscribe;
use core::fmt::Write;
use core::sync::atomic::{AtomicUsize, Ordering};

const ALARM_DRIVER: u32 = 0;
const CMD_FREQUENCY: u32 = 1;
const CMD_SET_RELATIVE: u32 = 5;
const INTERVAL_MS: u32 = 500;

static PEAK_USED: AtomicUsize = AtomicUsize::new(0);

async fn sleep_ms(ms: u32) {
    let freq: Result<u32, ErrorCode> =
        DefaultSyscalls::command(ALARM_DRIVER, CMD_FREQUENCY, 0, 0).to_result();
    let freq = freq.unwrap_or(1000);
    let ticks = ((ms as u64) * (freq as u64) / 1000) as u32;
    let sub = TockSubscribe::subscribe::<DefaultSyscalls>(ALARM_DRIVER, 0);
    let _ = DefaultSyscalls::command(ALARM_DRIVER, CMD_SET_RELATIVE, ticks, 0);
    let _ = sub.await;
}

#[embassy_executor::task]
pub async fn heap_monitor_task() {
    loop {
        let used = HEAP.used();
        let free = HEAP.free();
        let prev_peak = PEAK_USED.load(Ordering::Relaxed);
        if used > prev_peak {
            PEAK_USED.store(used, Ordering::Relaxed);
        }
        let peak = PEAK_USED.load(Ordering::Relaxed);
        let mut cw = Console::<DefaultSyscalls>::writer();
        writeln!(
            &mut cw,
            "HEAP total={} used={} free={} peak={}",
            HEAP_SIZE, used, free, peak
        )
        .ok();
        sleep_ms(INTERVAL_MS).await;
    }
}
