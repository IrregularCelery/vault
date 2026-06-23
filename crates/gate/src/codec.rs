pub mod binary {
    use crate::sys::vec::Vec;

    #[derive(Debug)]
    pub enum Error {
        OutOfBounds,
        InvalidUtf8,
    }

    pub struct Writer {
        output: Vec<u8>,
    }

    impl Writer {
        pub fn with_capacity(capacity: usize) -> Self {
            Self {
                output: Vec::with_capacity(capacity),
            }
        }

        pub fn write_u16(&mut self, value: u16) {
            self.output.extend_from_slice(&value.to_be_bytes());
        }

        pub fn write_u32(&mut self, value: u32) {
            self.output.extend_from_slice(&value.to_be_bytes());
        }

        pub fn write_u64(&mut self, value: u64) {
            self.output.extend_from_slice(&value.to_be_bytes());
        }

        pub fn write_bytes(&mut self, value: &[u8]) {
            self.output.extend_from_slice(value);
        }

        pub fn write_str_u16(&mut self, value: impl AsRef<str>) -> Result<(), Error> {
            let str = value.as_ref();
            let bytes = str.as_bytes();

            if bytes.len() > u16::MAX as usize {
                return Err(Error::OutOfBounds);
            }

            self.write_u16(bytes.len() as u16);
            self.write_bytes(bytes);

            Ok(())
        }

        pub fn finish(self) -> Vec<u8> {
            self.output
        }
    }

    pub struct Reader<'a> {
        input: &'a [u8],
        offset: usize,
    }

    impl<'a> Reader<'a> {
        pub fn new(input: &'a [u8]) -> Self {
            Self { input, offset: 0 }
        }

        pub fn read_u16(&mut self) -> Result<u16, Error> {
            let end = self.offset + 2;

            if end > self.input.len() {
                return Err(Error::OutOfBounds);
            }

            let mut bytes = [0u8; 2];

            bytes.copy_from_slice(&self.input[self.offset..end]);

            self.offset = end;

            Ok(u16::from_be_bytes(bytes))
        }

        pub fn read_u32(&mut self) -> Result<u32, Error> {
            let end = self.offset + 4;

            if end > self.input.len() {
                return Err(Error::OutOfBounds);
            }

            let mut bytes = [0u8; 4];

            bytes.copy_from_slice(&self.input[self.offset..end]);

            self.offset = end;

            Ok(u32::from_be_bytes(bytes))
        }

        pub fn read_u64(&mut self) -> Result<u64, Error> {
            let end = self.offset + 8;

            if end > self.input.len() {
                return Err(Error::OutOfBounds);
            }

            let mut bytes = [0u8; 8];

            bytes.copy_from_slice(&self.input[self.offset..end]);

            self.offset = end;

            Ok(u64::from_be_bytes(bytes))
        }

        pub fn read_bytes<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
            let end = self.offset + N;

            if end > self.input.len() {
                return Err(Error::OutOfBounds);
            }

            let slice = &self.input[self.offset..end];

            self.offset = end;

            slice.try_into().map_err(|_| Error::OutOfBounds)
        }

        pub fn read_str_u16(&mut self) -> Result<&'a str, Error> {
            let len = self.read_u16()? as usize;
            let end = self.offset + len;

            if end > self.input.len() {
                return Err(Error::OutOfBounds);
            }

            let bytes = &self.input[self.offset..end];

            self.offset = end;

            core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)
        }

        pub fn remaining(&self) -> usize {
            self.input.len() - self.offset
        }

        pub fn offset(&self) -> usize {
            self.offset
        }
    }
}
