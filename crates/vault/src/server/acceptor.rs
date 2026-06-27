use crate::{
    identity::Identity,
    protocol::{ClientInit, request::Request, response::Response},
    storage::{self, Backend, local},
    transport,
};

use gate::sys::{borrow::Cow, macros::format, path::PathBuf, string::ToString};

#[derive(Debug)]
pub enum Error {
    Transport(transport::Error),
    Storage(storage::Error),
    Other(Cow<'static, str>),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {}", e),
            Self::Storage(e) => write!(f, "storage: {}", e),
            Self::Other(e) => write!(f, "{}", e),
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
        // Retrieve `ClientInit` message
        let raw = transport.recv()?;
        let init = ClientInit::deserialize(&raw).map_err(|e| Error::Other(e.to_string().into()))?;
        let handshake_hash = transport.handshake_hash();
        let message = init.build_signing_message(&handshake_hash);

        if !Identity::verify_with_key(&init.signing_key, &message, &init.signature) {
            return Err(Error::Transport(transport::Error::Handshake(
                "client init signature does not match claimed identity",
            )));
        }

        let storage = local::Storage::new(&self.storage_root, &init.signing_key)?;

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
                        Ok(data) => Response::Manifest(data),
                        Err(storage::Error::NotFound) => Response::NotFound,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::PutBlob { address, data } => match storage.put_blob(&address, data) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::GetBlob { address } => match storage.get_blob(&address) {
                        Ok(data) => Response::Blob(data),
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
                    .map_err(|e| Error::Other(e.to_string().into()))?,
            )?;
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}
