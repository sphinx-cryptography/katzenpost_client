// pki.rs - pki client for katzenpost
// Copyright (C) 2021  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//!
//! PKI client for Katzenpost. This is the component of the Katzenpost
//! client that queries the voting authority system (also known as the
//! PKI) for a consensus document providing a view of the mix network
//! which includes public cryptographic key materials and connection
//! information for the entire network.
//!

extern crate mix_link;
extern crate x25519_dalek_ng;
extern crate socks;
extern crate retry;

use std::str::FromStr;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use socks::Socks5Stream;
use retry::{retry, OperationResult};
use retry::delay::Exponential;

use x25519_dalek_ng::{PublicKey, StaticSecret};

use mix_link::sync::Session;
use mix_link::messages::{PeerAuthenticator, ClientAuthenticatorState, SessionConfig};
use mix_link::commands::{Command};

use crate::errors::{ConnectError};


pub struct Client {
    socks_proxy_addr: Option<String>,
    server_addr: String,
    session_config: SessionConfig,
    session: Option<Session>,
}

impl Client {
    pub fn new(client_private_key: StaticSecret, server_public_key: PublicKey, server_addr: String) -> Client {
        let client_auth = ClientAuthenticatorState{
            peer_public_key: server_public_key.clone(),
        };
        let session_config = SessionConfig{
            authenticator: PeerAuthenticator::Client(client_auth),
            authentication_key: client_private_key,
            peer_public_key: Some(server_public_key),
            additional_data: vec![],
        };
        Client {
            socks_proxy_addr: None,
            server_addr: server_addr,
            session_config: session_config,
            session: None,
        }
    }

    fn server_stream(&self) -> Result<TcpStream, ConnectError> {
        let target = SocketAddr::from_str(&self.server_addr)?;
        if let Some(proxy_addr) = &self.socks_proxy_addr {
            return Ok(Socks5Stream::connect(SocketAddr::from_str(proxy_addr)?, target)?.into_inner());
        }
        return Ok(TcpStream::connect_timeout(&target, Duration::from_secs(45))?)
    }

    fn connect(&mut self) -> Result<(), ConnectError> {
        // Connect within 45 seconds.
        let mut session = Session::new(self.session_config.clone(), true)?;
        session.initialize(self.server_stream()?)?;
        session = session.into_transport_mode()?;
        session.finalize_handshake()?;
        self.session = Some(session);
        Ok(())
    }

    pub fn retry_connect(&mut self) -> Result<(), retry::Error<ConnectError>> {
        retry(Exponential::from(Duration::from_secs(5)).take(5), || {
            match self.connect() {
                Err(ConnectError::IOError(x)) => OperationResult::Retry(ConnectError::IOError(x)),
                Err(ConnectError::HandshakeError(x)) => OperationResult::Err(ConnectError::HandshakeError(x)),
                Err(ConnectError::AddrParseError(x)) => OperationResult::Err(ConnectError::AddrParseError(x)),
                Ok(()) => OperationResult::Ok(()),
            }
        })
    }

    pub fn close (&mut self) -> Result<(), ()> {
        self.session.as_mut().unwrap().close();
        Ok(())
    }
}


#[cfg(test)]
mod tests {

    #[test]
    fn pki_client_test() {
        let client = Client::new();
        
    }
}
