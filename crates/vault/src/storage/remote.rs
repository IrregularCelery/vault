//! Remote storage backend that proxies all storage operations over a [`transport::Backend`].
//!
//! Each method serializes a [`Request`], sends it, and deserializes the [`Response`].

use gate::sys::{macros::format, vec::Vec};

use crate::{
    protocol::{request::Request, response::Response},
    storage::{Backend, Error},
    transport,
};

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
    fn save_manifest(&self, data: &[u8]) -> Result<(), Error> {
        match self.roundtrip(Request::SaveManifest { data })? {
            Response::Ok => Ok(()),
            Response::Error(_) => Err(Error::Other("server error for `save_manifest`".into())),
            _ => Err(Error::Other(
                "unexpected response to `save_manifest`".into(),
            )),
        }
    }

    fn load_manifest(&self) -> Result<Vec<u8>, Error> {
        match self.roundtrip(Request::LoadManifest)? {
            Response::Manifest(data) => Ok(data),
            Response::NotFound => Err(Error::NotFound),
            Response::Error(_) => Err(Error::Other("server error for `load_manifest`".into())),
            _ => Err(Error::Other(
                "unexpected response to `load_manifest`".into(),
            )),
        }
    }

    fn put_blob(&self, address: &[u8; 32], data: &[u8]) -> Result<(), Error> {
        match self.roundtrip(Request::PutBlob {
            address: *address,
            data,
        })? {
            Response::Ok => Ok(()),
            Response::Error(_) => Err(Error::Other("server error for `put_blob`".into())),
            _ => Err(Error::Other("unexpected response to `put_blob`".into())),
        }
    }

    fn get_blob(&self, address: &[u8; 32]) -> Result<Vec<u8>, Error> {
        match self.roundtrip(Request::GetBlob { address: *address })? {
            Response::Blob(data) => Ok(data),
            Response::Error(_) => Err(Error::Other("server error for `get_blob`".into())),
            _ => Err(Error::Other("unexpected response to `get_blob`".into())),
        }
    }

    fn exists_blob(&self, address: &[u8; 32]) -> Result<bool, Error> {
        match self.roundtrip(Request::ExistsBlob { address: *address })? {
            Response::Exists(exists) => Ok(exists),
            Response::Error(_) => Err(Error::Other("server error for `exists_blob`".into())),
            _ => Err(Error::Other("unexpected response to `exists_blob`".into())),
        }
    }

    fn delete_blob(&self, address: &[u8; 32]) -> Result<(), Error> {
        match self.roundtrip(Request::DeleteBlob { address: *address })? {
            // Response::NotFound is actually redundant since the server never returns it
            Response::Ok | Response::NotFound => Ok(()),
            Response::Error(_) => Err(Error::Other("server error for `delete_blob`".into())),
            _ => Err(Error::Other("unexpected response to `delete_blob`".into())),
        }
    }

    fn list_blobs(&self) -> Result<Vec<[u8; 32]>, Error> {
        match self.roundtrip(Request::ListBlobs)? {
            Response::Addresses(addresses) => Ok(addresses),
            Response::Error(_) => Err(Error::Other("server error for `list_blobs`".into())),
            _ => Err(Error::Other("unexpected response to `list_blobs`".into())),
        }
    }
}
