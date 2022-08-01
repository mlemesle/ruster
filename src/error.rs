use thiserror::Error;

#[derive(Debug, Error)]
pub enum PacketDecodeError {
    #[error("Error while parsing the IP version")]
    UnknownIpVersion,
    #[error("Error while parsing the protocol")]
    UnknownProtocol,
    #[error("Error while attempting to decode headers. Header size should be between 20 and 60 bytes long, got {0}")]
    HeaderBufferSize(usize),
    #[error("Error while reading data")]
    InvalidData,
}
