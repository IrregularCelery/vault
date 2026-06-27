use crate::{
    identity::Identity,
    protocol::ClientInit,
    session::{self, Session},
    storage::remote,
    transport,
};

use gate::sys::{borrow::Cow, string::ToString, time};

#[derive(Debug)]
pub enum Error {
    Transport(transport::Error),
    Session(session::Error),
    Other(Cow<'static, str>),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {}", e),
            Self::Session(e) => write!(f, "session: {}", e),
            Self::Other(e) => write!(f, "{}", e),
        }
    }
}

impl From<transport::Error> for Error {
    fn from(value: transport::Error) -> Self {
        Self::Transport(value)
    }
}

impl From<session::Error> for Error {
    fn from(value: session::Error) -> Self {
        Self::Session(value)
    }
}

pub struct ConnectedClient<T: transport::Backend> {
    session: Session<remote::Storage<T>>,
    server_static_key: [u8; 32],
}

impl<T: transport::Backend> ConnectedClient<T> {
    pub fn into_session(self) -> Session<remote::Storage<T>> {
        self.session
    }

    pub fn session(&self) -> &Session<remote::Storage<T>> {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut Session<remote::Storage<T>> {
        &mut self.session
    }

    pub fn server_static_key(&self) -> &[u8; 32] {
        &self.server_static_key
    }
}

pub struct Client {
    identity: Identity,
    expected_server_key: [u8; 32],
}

impl Client {
    pub fn new(identity: Identity, expected_server_key: [u8; 32]) -> Self {
        Self {
            identity,
            expected_server_key,
        }
    }

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
        let message = ClientInit {
            signing_key,
            exchange_key,
            timestamp,
            signature: [0u8; 64],
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
            .send(
                &init
                    .serialize()
                    .map_err(|e| Error::Other(e.to_string().into()))?,
            )
            .map_err(|_| {
                Error::Transport(transport::Error::Handshake("failed to send `client init`"))
            })?;

        let server_static_key = transport.peer_static_key();
        let storage = remote::Storage::new(transport);
        let session = Session::new(self.identity, storage)?;

        Ok(ConnectedClient {
            session,
            server_static_key,
        })
    }
}
