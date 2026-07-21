//! Establishes an authenticated connection to a vault server.

use crate::{
    identity::Identity,
    protocol::{self, ClientInit},
    storage::remote,
    transport,
    vault::{self, Vault},
};

use gate::sys::time;

/// Errors from client connection setup and vault initialization.
#[derive(Debug)]
pub enum Error {
    /// A transport-level failure.
    Transport(transport::Error),

    /// A vault initialization failure.
    Vault(vault::Error),

    /// A binary serialization or deserialization error.
    Codec(protocol::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {}", e),
            Self::Vault(e) => write!(f, "vault: {}", e),
            Self::Codec(e) => write!(f, "codec: {}", e),
        }
    }
}

impl From<transport::Error> for Error {
    fn from(value: transport::Error) -> Self {
        Self::Transport(value)
    }
}

impl From<vault::Error> for Error {
    fn from(value: vault::Error) -> Self {
        Self::Vault(value)
    }
}

/// A successfully connected and authenticated client.
///
/// Wraps a [`Vault`] backed by a [`remote::Storage`] over the established transport.
pub struct ConnectedClient<T: transport::Backend> {
    /// The active vault session backed by remote storage over the established transport.
    vault: Vault<remote::Storage<T>>,

    /// The server's verified static public key as established during the handshake.
    server_static_key: [u8; 32],
}

impl<T: transport::Backend> ConnectedClient<T> {
    /// Consumes the connected client and returns the inner [`Vault`].
    pub fn into_vault(self) -> Vault<remote::Storage<T>> {
        self.vault
    }

    /// Returns a reference to the inner [`Vault`].
    pub fn vault(&self) -> &Vault<remote::Storage<T>> {
        &self.vault
    }

    /// Returns a mutable reference to the inner [`Vault`].
    pub fn vault_mut(&mut self) -> &mut Vault<remote::Storage<T>> {
        &mut self.vault
    }

    /// Returns the server's verified static public key as established during the handshake.
    pub fn server_static_key(&self) -> &[u8; 32] {
        &self.server_static_key
    }
}

/// A pre-connection client configured with an identity and the expected server key.
pub struct Client {
    /// The user's cryptographic identity used to authenticate and encrypt the vault.
    identity: Identity,

    /// The static public key the server is expected to present during the handshake.
    /// The connection is aborted if the actual key differs, preventing MITM attacks.
    expected_server_key: [u8; 32],
}

impl Client {
    /// Creates a new client.
    ///
    /// `expected_server_key` is the server's static public key. The connection will be rejected
    /// if the server presents a different key, preventing MITM attacks.
    pub fn new(identity: Identity, expected_server_key: [u8; 32]) -> Self {
        Self {
            identity,
            expected_server_key,
        }
    }

    /// Performs the post-transport application-level handshake and returns a [`ConnectedClient`].
    ///
    /// Protocol flow:
    /// 1. Verify the server's static key against `expected_server_key`.
    /// 2. Build a [`ClientInit`] message and sign it.
    /// 3. Send [`ClientInit`] to authenticate this identity to the server.
    /// 4. Wrap the transport in a [`remote::Storage`] and open a [`Vault`].
    pub fn connect<T: transport::Backend>(
        self,
        mut transport: T,
    ) -> Result<ConnectedClient<T>, Error> {
        if transport.peer_static_key() != self.expected_server_key {
            return Err(Error::Transport(transport::Error::Handshake(
                "server static key does not match expected key",
            )));
        }

        let signing_key = self.identity.public_signing_key();
        let exchange_key = self.identity.public_exchange_key();
        let timestamp = time::current_secs().unwrap_or(0);
        let handshake_hash = transport.handshake_hash();
        // Build a temporary `ClientInit` with a zero signature just to produce the byte sequence
        // that will be signed. The `signature` field is excluded from the signed message
        // by `build_signing_message`, so the placeholder value doesn't matter.
        let message = ClientInit {
            signing_key,
            exchange_key,
            timestamp,
            signature: [0u8; 64], // Placeholder, not part of the signed message
        }
        .build_signing_message(&handshake_hash);
        let signature = self.identity.sign(&message);

        let init = ClientInit {
            signing_key,
            exchange_key,
            timestamp,
            signature,
        };

        transport
            .send(&init.serialize().map_err(Error::Codec)?)
            .map_err(|_| {
                Error::Transport(transport::Error::Handshake("failed to send `client init`"))
            })?;

        let server_static_key = transport.peer_static_key();
        let storage = remote::Storage::new(transport);
        let vault = Vault::open(self.identity, storage)?;

        Ok(ConnectedClient {
            vault,
            server_static_key,
        })
    }
}
