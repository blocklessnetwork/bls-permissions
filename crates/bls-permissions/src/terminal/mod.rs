#![allow(dead_code)]

use std::io::IsTerminal;

use once_cell::sync::Lazy;

pub mod colors;

static IS_STDOUT_TTY: Lazy<bool> = Lazy::new(|| std::io::stdout().is_terminal());
static IS_STDERR_TTY: Lazy<bool> = Lazy::new(|| std::io::stderr().is_terminal());

pub fn is_stdout_tty() -> bool {
    *IS_STDOUT_TTY
}

pub fn is_stderr_tty() -> bool {
    *IS_STDERR_TTY
}
