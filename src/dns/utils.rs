extern crate time;

use std::thread;

pub fn current_time_millis() -> u64 { time::precise_time_ns() / 1000000 }

pub fn current_thread_name() -> String {
    match thread::current().name() {
        Some(name) => {
            name.to_owned()
        },
        None => {
            format!("{:?}", thread::current().id())
        }
    }
}