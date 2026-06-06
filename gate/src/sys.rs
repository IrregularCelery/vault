pub mod macros {
    pub use std::dbg;
    pub use std::format;
    pub use std::print;
    pub use std::println;
    pub use std::vec;
}

pub mod vec {
    pub use std::vec::*;
}

pub mod string {
    pub use std::string::*;
}

pub mod boxed {
    pub use std::boxed::*;
}

pub mod borrow {
    pub use std::borrow::*;
}

pub mod collections {
    pub use std::collections::*;
}

pub mod rc {
    pub use std::rc::*;
}

pub mod cell {
    pub use std::cell::*;
}

pub mod sync {
    pub use std::sync::*;
}

pub mod fmt {
    pub use std::fmt::*;
}

pub mod iter {
    pub use std::iter::*;
}

pub mod io {
    pub use std::io::*;
}

pub mod path {
    pub use std::path::*;
}

pub mod time {
    pub use std::time::*;
}

pub mod random {
    pub use rand::Rng;
    pub use rand::rng;
}
