// Should probably be feature-gated
extern crate std;

pub mod macros {
    pub use super::std::dbg;
    pub use super::std::eprint;
    pub use super::std::eprintln;
    pub use super::std::format;
    pub use super::std::print;
    pub use super::std::println;
    pub use super::std::vec;
}

pub mod vec {
    pub use super::std::vec::*;
}

pub mod string {
    pub use super::std::string::*;
}

pub mod boxed {
    pub use super::std::boxed::*;
}

pub mod borrow {
    pub use super::std::borrow::*;
}

pub mod collections {
    pub use super::std::collections::*;
}

pub mod rc {
    pub use super::std::rc::*;
}

pub mod cell {
    pub use super::std::cell::*;
}

pub mod sync {
    pub use super::std::sync::*;
}

pub mod fmt {
    pub use super::std::fmt::*;
}

pub mod iter {
    pub use super::std::iter::*;
}

pub mod io {
    pub use super::std::io::*;
}

pub mod fs {
    pub use super::std::fs::*;
}

pub mod path {
    pub use super::std::path::*;
}

pub mod time {
    pub use super::std::time::*;
}

pub mod thread {
    pub use super::std::thread::*;
}

pub mod env {
    pub use super::std::env::*;
}

pub mod random {
    pub use rand::Rng;
    pub use rand::rng;
}
