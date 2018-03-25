extern crate time;

pub fn current_time_millis() -> u64 { time::precise_time_ns() / 1000000 }