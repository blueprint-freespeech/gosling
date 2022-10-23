use std::fmt;

pub struct Error {
    message: String,
    line: u32,
    file: &'static str,
}

impl Error {
    pub fn new(message: String, line: u32, file: &'static str) -> Self{
        Self{message, line, file}
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.message)
    }
}

pub type Result<T, E = Error> = core::result::Result<T,E>;

mod error_macros {
    #[macro_export]
    macro_rules! error {
        ($err:tt) => {
            {
                let message = $err.to_string();
                let line = std::line!();
                let file = std::file!();
                Err(error::Error::new(message,line,file))
            }
        };
    }

    #[macro_export]
    macro_rules! bail {
        ($msg:literal) => {
            {
                return error!($msg);
            }
        };
        ($err:expr) => {
            {
                return error!($err);
            }
        };
        ($fmt:literal, $($arg:tt)*) => {
            {
                let message = std::format!($fmt, $($arg)*);
                return error!(message);
            }
        };
    }

    #[macro_export]
    macro_rules! resolve {
        ($result:expr) => {
            match $result {
                Ok(val) => val,
                Err(err) => bail!(err),
            }
        }
    }

    #[macro_export]
    macro_rules! ensure {
        ($condition:expr) => {
            if !$condition {
                bail!(std::format!("`{}` requirement failed", std::stringify!($condition)));
            }
        };
        ($condition:expr, $msg:literal) => {
            if !$condition {
                bail!($msg);
            }
        };
        ($condition:expr, $fmt:literal, $($arg:tt)*) => {
            if !$condition {
                bail!($fmt, $($arg)*);
            }
        };
    }
}
