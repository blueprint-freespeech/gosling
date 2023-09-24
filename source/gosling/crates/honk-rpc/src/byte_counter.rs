use std::io::Write;

#[derive(Default)]
pub(crate) struct ByteCounter {
    bytes: usize,
}

impl ByteCounter {
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.bytes += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}