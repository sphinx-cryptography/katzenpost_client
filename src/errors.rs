// errors.rs - client errors
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

use std::error::{Error};
use std::fmt;

use mix_link::errors::HandshakeError;


#[derive(Debug)]
pub enum ConnectError {
    ConnectFailure,
    HandshakeError(HandshakeError),
    IOError(std::io::Error)
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConnectError::ConnectFailure => write!(f, "Failure to connect."),
            ConnectError::HandshakeError(_) => write!(f, "Handshake failure."),
            ConnectError::IOError(x) => x.fmt(f),
        }
    }
}

impl Error for ConnectError {
    fn description(&self) -> &str {
        "I'm a connect error."
    }

    fn cause(&self) -> Option<&dyn Error> {
        match self {
            ConnectError::ConnectFailure => None,
            ConnectError::HandshakeError(x) => x.source(),
            ConnectError::IOError(x) => x.source(),
        }
    }
}

impl From<HandshakeError> for ConnectError {
    fn from(error: HandshakeError) -> Self {
        ConnectError::HandshakeError(error)
    }
}


impl From<std::io::Error> for ConnectError {
    fn from(error: std::io::Error) -> Self {
        ConnectError::IOError(error)
    }
}
