//! Remote storage backend that proxies all storage operations over a [`transport::Backend`].
//!
//! Each method serializes a [`Request`], sends it, and deserializes the [`Response`].

use crate::{
    protocol::{request::Request, response::Response},
    storage::{Backend, Error, Key, Kind},
    transport,
};

use gate::sys::{macros::format, vec::Vec};

/// A storage backend that delegates all operations to a remote server.
pub struct Storage<T: transport::Backend> {
    /// The underlying transport channel.
    transport: core::cell::RefCell<T>,
}

impl<T: transport::Backend> Storage<T> {
    /// Creates a new [`Storage`] instance and wraps a successfully established `transport`.
    pub fn new(transport: T) -> Self {
        Self {
            transport: core::cell::RefCell::new(transport),
        }
    }

    /// Serializes `request`, sends it over the transport, waits for the response, and deserialize
    /// it. Propagates codec and transport failures as [`Error`].
    fn roundtrip(&self, request: Request) -> Result<Response, Error> {
        let mut transport = self.transport.borrow_mut();

        transport.send(
            &request
                .serialize()
                .map_err(|e| Error::Other(format!("request codec error: {}", e).into()))?,
        )?;

        let raw = transport.recv()?;

        Response::deserialize(&raw)
            .map_err(|e| Error::Other(format!("response codec error: {}", e).into()))
    }
}

impl<T: transport::Backend> Backend for Storage<T> {
    fn put(&self, key: Key, data: &[u8]) -> Result<(), Error> {
        match self.roundtrip(Request::Put { key, data })? {
            Response::Ok => Ok(()),
            Response::Error(_) => Err(Error::Other("server error for `put`".into())),
            _ => Err(Error::Other("unexpected response to `put`".into())),
        }
    }

    fn get(&self, key: Key) -> Result<Vec<u8>, Error> {
        match self.roundtrip(Request::Get { key })? {
            Response::Data(data) => Ok(data),
            Response::NotFound => Err(Error::NotFound),
            Response::Error(_) => Err(Error::Other("server error for `get`".into())),
            _ => Err(Error::Other("unexpected response to `get`".into())),
        }
    }

    fn exists(&self, key: Key) -> Result<bool, Error> {
        match self.roundtrip(Request::Exists { key })? {
            Response::Exists(exists) => Ok(exists),
            Response::Error(_) => Err(Error::Other("server error for `exists`".into())),
            _ => Err(Error::Other("unexpected response to `exists`".into())),
        }
    }

    fn delete(&self, key: Key) -> Result<(), Error> {
        match self.roundtrip(Request::Delete { key })? {
            // Response::NotFound is actually redundant since the server never returns it
            Response::Ok | Response::NotFound => Ok(()),
            Response::Error(_) => Err(Error::Other("server error for `delete`".into())),
            _ => Err(Error::Other("unexpected response to `delete`".into())),
        }
    }

    fn list(&self, kind: Kind) -> Result<Vec<Key>, Error> {
        match self.roundtrip(Request::List { kind })? {
            Response::Keys(keys) => Ok(keys),
            Response::Error(_) => Err(Error::Other("server error for `list`".into())),
            _ => Err(Error::Other("unexpected response to `list`".into())),
        }
    }
}
