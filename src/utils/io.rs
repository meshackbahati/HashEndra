use std::sync::Mutex;

lazy_static::lazy_static! {
    pub static ref STDOUT_MUTEX: Mutex<()> = Mutex::new(());
}

#[macro_export]
macro_rules! safe_println {
    ($($arg:tt)*) => {
        {
            use ::std::io::Write;
            let _lock = $crate::utils::io::STDOUT_MUTEX.lock().unwrap();
            if let Err(e) = writeln!(::std::io::stdout(), $($arg)*) {
                if e.kind() == ::std::io::ErrorKind::BrokenPipe {
                    ::std::process::exit(0);
                }
                panic!("IO error: {}", e);
            }
        }
    }
}

#[macro_export]
macro_rules! safe_print {
    ($($arg:tt)*) => {
        {
            use ::std::io::Write;
            let _lock = $crate::utils::io::STDOUT_MUTEX.lock().unwrap();
            if let Err(e) = write!(::std::io::stdout(), $($arg)*) {
                if e.kind() == ::std::io::ErrorKind::BrokenPipe {
                    ::std::process::exit(0);
                }
                panic!("IO error: {}", e);
            }
        }
    }
}
