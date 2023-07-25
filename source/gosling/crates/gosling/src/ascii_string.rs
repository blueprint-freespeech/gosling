#[cfg(test)]
use anyhow::bail;
use std::ops::Deref;

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("input string is not ASCII: {0}")]
    InvalidAscii(String),
}

/// An immutable wrapper around a String guaranteed to be ASCII encoded
#[derive(Clone, PartialEq)]
pub(crate) struct AsciiString {
    value: String,
}

impl AsciiString {
    pub fn new(value: String) -> Result<AsciiString, Error> {
        if value.is_ascii() {
            Ok(Self { value })
        } else {
            Err(Error::InvalidAscii(value))
        }
    }
}

impl Deref for AsciiString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl std::fmt::Debug for AsciiString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl std::fmt::Display for AsciiString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

#[test]
fn test_ascii_string() -> anyhow::Result<()> {
    let valid_ascii: [String; 8] = [
        "".to_string(),
        " !\"#$%&'()*+,-./".to_string(),
        "0123456789".to_string(),
        ":<=>?@".to_string(),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string(),
        "[\\]^_`".to_string(),
        "abcdefghijklmnopqstuvwxyz".to_string(),
        "{|}~".to_string(),
    ];

    for string in valid_ascii {
        match AsciiString::new(string) {
            Ok(string) => println!("ascii: '{}'", string),
            Err(err) => bail!("unexpected error: {}", err),
        }
    }

    let utf8: [String; 2] = ["❤".to_string(), "heart ❤".to_string()];

    for string in utf8 {
        match AsciiString::new(string) {
            Ok(string) => bail!("this is not ascii: {}", string),
            Err(_) => (),
        }
    }

    Ok(())
}
