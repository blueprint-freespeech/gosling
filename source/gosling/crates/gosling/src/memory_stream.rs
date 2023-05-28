// standard
use std::convert::From;
use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

// a test-only mock TcpStream
#[derive(Clone)]
pub struct MemoryStream {
    stream: Arc<Mutex<Vec<u8>>>,
    read_head: usize,
}

impl MemoryStream {
    pub fn new() -> Self {
        return Self {
            stream: Default::default(),
            read_head: 0,
        };
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let read_buf = match self.stream.lock() {
            Ok(read_buf) => read_buf,
            Err(_) => unreachable!(),
        };
        let read_head = self.read_head;
        let read_tail: usize = (read_head + buf.len()).min(read_buf.len());

        let byte_count = read_tail - read_head;
        if byte_count == 0 {
            return Err(std::io::Error::from(ErrorKind::WouldBlock));
        } else {
            for i in read_head..read_tail {
                buf[i - read_head] = read_buf[i];
            }
            self.read_head = read_tail;
            return Ok(byte_count);
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize, std::io::Error> {
        let read_buf = match self.stream.lock() {
            Ok(read_buf) => read_buf,
            Err(_) => unreachable!(),
        };
        let read_head = self.read_head;
        let read_tail = read_buf.len();
        let byte_count = read_tail - read_head;
        if byte_count == 0 {
            return Err(std::io::Error::from(ErrorKind::WouldBlock));
        }
        buf.extend_from_slice(&read_buf.as_slice()[read_head..read_tail]);
        self.read_head = read_tail;
        return Ok(byte_count);
    }
}

impl Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let mut write_buf = match self.stream.lock() {
            Ok(read_buf) => read_buf,
            Err(_) => unreachable!(),
        };
        write_buf.extend_from_slice(buf);
        return Ok(buf.len());
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        return Ok(());
    }
}

#[test]
fn test_memory_stream() -> anyhow::Result<()> {
    let mut stream1 = MemoryStream::new();
    let mut stream2 = stream1.clone();

    const MESSAGE: &str = "hello_world!";

    stream1.write_all(MESSAGE.as_bytes())?;
    let mut msg_buff: Vec<u8> = Default::default();
    assert!(stream2.read_to_end(&mut msg_buff)? == MESSAGE.len());

    match stream2.read_to_end(&mut msg_buff) {
        Err(err) => assert!(err.kind() == ErrorKind::WouldBlock),
        Ok(_) => panic!("should have returned ErrorKind::WouldBlock"),
    }

    let msg = std::str::from_utf8(&msg_buff)?;

    assert!(msg == MESSAGE);

    let mut buf = [0u8; 16];
    match stream2.read(&mut buf) {
        Err(err) => assert!(err.kind() == ErrorKind::WouldBlock),
        Ok(_) => panic!("should have returned ErrorKind::WouldBlock"),
    }

    println!("recieved string: '{}'", msg);

    return Ok(());
}
