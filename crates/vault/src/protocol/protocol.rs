use gate::codec::binary;

#[derive(Debug)]
pub enum Error {
    Codec(binary::Error),
    UnknownTag(u8),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(e) => write!(f, "codec: {}", e),
            Self::UnknownTag(t) => write!(f, "unknown tag: {}", t),
        }
    }
}

impl From<binary::Error> for Error {
    fn from(value: binary::Error) -> Self {
        Self::Codec(value)
    }
}
