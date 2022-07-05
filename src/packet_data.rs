use crate::error::PacketDecodeError;

pub trait PacketData<T>
where
    Self: Sized,
{
    fn from_source(buffer: T) -> Result<Self, PacketDecodeError>;
}

impl PacketData<&[u8]> for String {
    fn from_source(buffer: &[u8]) -> Result<Self, PacketDecodeError> {
        match std::str::from_utf8(buffer) {
            Ok(s) => Ok(s.trim_end_matches('\0').to_owned()),
            Err(_) => Err(PacketDecodeError::InvalidData),
        }
    }
}
