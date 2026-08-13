//! Handles a single authenticated client connection from handshake to request loop.

use crate::{
    identity::Identity,
    protocol::{self, ClientInit, request::Request, response::Response},
    storage::{self, Backend, local},
    transport,
};

use gate::sys::{macros::format, path::PathBuf, string::ToString};

/// Errors that can occur while accepting or serving a client connection.
#[derive(Debug)]
pub enum Error {
    /// A transport-level failure.
    Transport(transport::Error),

    /// A blob or index shard storage operation failed.
    Storage(storage::Error),

    /// A binary serialization or deserialization error.
    Codec(protocol::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {}", e),
            Self::Storage(e) => write!(f, "storage: {}", e),
            Self::Codec(e) => write!(f, "codec: {}", e),
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

/// A vault server that authenticates clients and dispatches storage operations.
///
/// Each call to [`Server::accept`] handles exactly one client connection for its lifetime.
/// The server holds its own [`Identity`] and a root directory under which per-user storage
/// is scoped.
pub struct Server {
    /// The server's own cryptographic identity.
    identity: Identity,

    /// Root directory under which per-user storage directories are created.
    storage_root: PathBuf,
}

impl Server {
    /// Creates a new server with `identity` and `storage_root`.
    pub fn new(identity: Identity, storage_root: impl Into<PathBuf>) -> Self {
        Self {
            identity,
            storage_root: storage_root.into(),
        }
    }

    /// Accepts a successfully established transport and serves the client for its lifetime.
    ///
    /// Protocol flow:
    /// 1. Receive and deserialize [`ClientInit`].
    /// 2. Verify the client's claimed identity using a signature over a version of [`ClientInit`].
    /// 3. Open a [`local::Storage`] scoped to the client's public signing key.
    /// 4. Enter a request/response loop, dispatching each [`Request`] variant to the
    ///    matching [`storage::Backend`] method and serialising the [`Response`].
    ///
    /// # Errors
    ///
    /// - [`Error::Transport`]: If the client application-level verification, or the transport
    ///   message transfer fails.
    /// - [`Error::Storage`]: If an underlying storage error happens.
    /// - [`Error::Codec`]: If serialization or deserialization fails.
    pub fn accept<T: transport::Backend>(&self, mut transport: T) -> Result<(), Error> {
        // Retrieve `ClientInit` message
        let raw = transport.recv()?;
        let init = ClientInit::deserialize(&raw).map_err(Error::Codec)?;
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
                // A clean disconnect from the client is fine, not an error.
                Err(transport::Error::Closed) => return Ok(()),
                Err(e) => return Err(Error::Transport(e)),
            };
            // FIXME: Server shouldn't return every error to clients. (e.g., I/O errors)
            // Perhaps even log them to console and stuff.
            // NOTE: We could even have a server-side blob integrity check. Which means we probably
            // store user's public signing key as a field in the server.
            let response = match Request::deserialize(&raw) {
                Ok(request) => match request {
                    Request::Put { key, data } => match storage.put(key, data) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::Get { key } => match storage.get(key) {
                        Ok(data) => Response::Data(data),
                        Err(storage::Error::NotFound) => Response::NotFound,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::Exists { key } => match storage.exists(key) {
                        Ok(exists) => Response::Exists(exists),
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::Delete { key } => match storage.delete(key) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error(e.to_string()),
                    },
                    Request::List { kind } => match storage.list(kind) {
                        Ok(keys) => Response::Keys(keys),
                        Err(e) => Response::Error(e.to_string()),
                    },
                },
                Err(e) => Response::Error(format!("error while deserializing request: {}", e)),
            };

            transport.send(&response.serialize().map_err(Error::Codec)?)?;
        }
    }

    /// Returns a reference to the server's [`Identity`].
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
}
