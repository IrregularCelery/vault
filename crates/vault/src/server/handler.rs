use crate::{
    identity::Identity,
    protocol::{request::Request, response::Response},
    storage::{self, Backend, local},
    transport,
};

use gate::sys::{
    borrow::Cow,
    macros::format,
    path::PathBuf,
    string::{String, ToString},
};

#[derive(Debug)]
pub enum Error {
    Transport(transport::Error),
    Storage(storage::Error),
    Other(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "transport: {}", e),
            Error::Storage(e) => write!(f, "storage: {}", e),
            Error::Other(e) => write!(f, "{}", e),
        }
    }
}

impl From<transport::Error> for Error {
    fn from(value: transport::Error) -> Self {
        Self::Transport(value)
    }
}

impl From<storage::Error> for Error {
    fn from(value: storage::Error) -> Self {
        Self::Storage(value)
    }
}

pub struct Server {
    identity: Identity,
    storage_root: PathBuf,
}

impl Server {
    pub fn new(identity: Identity, storage_root: impl Into<PathBuf>) -> Self {
        Self {
            identity,
            storage_root: storage_root.into(),
        }
    }

    pub fn accept<T: transport::Backend>(&self, mut transport: T) -> Result<(), Error> {
        // TODO: Do a client identity check claim here. (public signing and exchange keys)
        // Client must provide a [`ClientInit`] for the first message after a successful handshake,
        // and there's an artifact that both the server and the client can independently derive from
        // the handshake, and can verify the user's claimed keys.

        let client_public_signing_key = [0x0u8; 32];

        let storage = local::Storage::new(&self.storage_root, &client_public_signing_key)?;

        loop {
            let raw = match transport.recv() {
                Ok(r) => r,
                Err(transport::Error::Closed) => return Ok(()),
                Err(e) => return Err(Error::Transport(e)),
            };
            let response = match Request::deserialize(&raw) {
                Ok(request) => match request {
                    Request::SaveManifest { data } => match storage.save_manifest(data) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::LoadManifest => match storage.load_manifest() {
                        Ok(data) => Response::Manifest(Cow::Owned(data)),
                        Err(storage::Error::NotFound) => Response::NotFound,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::PutBlob { address, data } => match storage.put_blob(&address, data) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::GetBlob { address } => match storage.get_blob(&address) {
                        Ok(data) => Response::Blob(Cow::Owned(data)),
                        Err(storage::Error::NotFound) => Response::NotFound,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::ExistsBlob { address } => match storage.exists_blob(&address) {
                        Ok(exists) => Response::Exists(exists),
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::DeleteBlob { address } => match storage.delete_blob(&address) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::ListBlobs => match storage.list_blobs() {
                        Ok(addresses) => Response::Addresses(addresses),
                        Err(e) => Response::Error(e.to_string()),
                    },
                },
                Err(e) => Response::Error(format!("error while deserializing request: {}", e)),
            };

            transport.send(
                &response
                    .serialize()
                    .map_err(|e| Error::Other(e.to_string()))?,
            )?;
        }
    }
}
