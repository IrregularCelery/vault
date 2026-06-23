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

        pub fn write_u8(&mut self, value: u8) {
            self.output.extend_from_slice(&value.to_be_bytes());
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

        pub fn write_blob(&mut self, value: &[u8]) -> Result<(), Error> {
            if value.len() > u32::MAX as usize {
                return Err(Error::OutOfBounds);
            }

            self.write_u32(value.len() as u32);
            self.write_bytes(value);

            Ok(())
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

        pub fn read_u8(&mut self) -> Result<u8, Error> {
            let end = self.offset + 1;

            if end > self.input.len() {
                return Err(Error::OutOfBounds);
            }

            let mut bytes = [0u8; 1];

            bytes.copy_from_slice(&self.input[self.offset..end]);

            self.offset = end;

            Ok(u8::from_be_bytes(bytes))
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

            let bytes = &self.input[self.offset..end];

            self.offset = end;

            bytes.try_into().map_err(|_| Error::OutOfBounds)
        }

        pub fn read_blob(&mut self) -> Result<&'a [u8], Error> {
            let len = self.read_u32()? as usize;
            let end = self.offset + len;

            if end > self.input.len() {
                return Err(Error::OutOfBounds);
            }

            let bytes = &self.input[self.offset..end];

            self.offset = end;

            Ok(bytes)
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn serialize_deserialize_roundtrip() {
            let mut writer = Writer::with_capacity(15);

            writer.write_u8(69);
            writer.write_u16(0xFEED);
            writer.write_u32(0xDEADBEEF);
            writer.write_u64(0x0123456789ABCDEF);

            let data = writer.finish();
            let mut reader = Reader::new(&data);

            assert_eq!(reader.read_u8().unwrap(), 69);
            assert_eq!(reader.read_u16().unwrap(), 0xFEED);
            assert_eq!(reader.read_u32().unwrap(), 0xDEADBEEF);
            assert_eq!(reader.read_u64().unwrap(), 0x0123456789ABCDEF);
            assert_eq!(reader.remaining(), 0);
        }

        #[test]
        fn bytes_and_blobs() {
            let mut writer = Writer::with_capacity(50);

            let address = [0xAAu8; 32];

            // Write fixed raw bytes
            writer.write_bytes(&address);

            let blob_data = b"hello, secure world";

            // Write a dynamic blob (length prefixed)
            writer.write_blob(blob_data).unwrap();

            // Write a short string
            writer.write_str_u16("vault").unwrap();

            let data = writer.finish();
            let mut reader = Reader::new(&data);

            assert_eq!(reader.read_bytes::<32>().unwrap(), &address);
            assert_eq!(reader.read_blob().unwrap(), blob_data);
            assert_eq!(reader.read_str_u16().unwrap(), "vault");
            assert_eq!(reader.remaining(), 0);
        }

        #[test]
        fn reader_out_of_bounds() {
            let mut writer = Writer::with_capacity(2);

            writer.write_u16(100);

            let data = writer.finish();
            let mut reader = Reader::new(&data);

            // Consumes the only 2 bytes
            assert!(reader.read_u16().is_ok());

            // Any subsequent read hits bounds boundary
            assert!(matches!(reader.read_u8(), Err(Error::OutOfBounds)));
            assert!(matches!(reader.read_u32(), Err(Error::OutOfBounds)));
            assert!(matches!(reader.read_bytes::<4>(), Err(Error::OutOfBounds)));
            assert!(matches!(reader.read_blob(), Err(Error::OutOfBounds)));
        }

        #[test]
        fn corrupted_blob_length() {
            let mut writer = Writer::with_capacity(4);

            // Write a u32 size prefix as if 500 bytes of data is behind (after) it, but write nothing
            writer.write_u32(500);

            let data = writer.finish();
            let mut reader = Reader::new(&data);

            assert!(matches!(reader.read_blob(), Err(Error::OutOfBounds)));
        }

        #[test]
        fn invalid_utf8() {
            let mut writer = Writer::with_capacity(6);

            writer.write_u16(4);

            // 0xFF is an invalid UTF-8 byte
            writer.write_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]);

            let data = writer.finish();
            let mut reader = Reader::new(&data);

            assert!(matches!(reader.read_str_u16(), Err(Error::InvalidUtf8)));
        }
    }
}
