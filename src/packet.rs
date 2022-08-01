use std::{marker::PhantomData, net::Ipv4Addr};

use crate::{error::PacketDecodeError, packet_data::PacketData, MTU};

#[derive(Debug)]
pub struct Packet<'a, T>
where
    T: PacketData<&'a [u8]>,
{
    pub headers: Headers,
    pub data: T,
    pub pdata: PhantomData<&'a ()>,
}

impl<'a, T> TryFrom<&'a [u8; MTU]> for Packet<'a, T>
where
    T: PacketData<&'a [u8]>,
{
    type Error = PacketDecodeError;

    fn try_from(buf: &'a [u8; MTU]) -> Result<Self, Self::Error> {
        let headers = Headers::try_from(&buf[0..60])?;
        let data = T::from_source(&buf[((headers.header_length as usize * 4) + 1)..])?;

        let packet = Packet::<T> {
            headers,
            data,
            pdata: PhantomData::default(),
        };
        Ok(packet)
    }
}

#[derive(Debug)]
pub struct Headers {
    pub ip_version: IpVersion,
    pub header_length: u8,
    pub type_of_service: TypeOfService,
    pub total_length: u16,
    pub identifier: u16,
    pub flags: Flags,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub header_checksum: u16,
    pub source_address: Ipv4Addr,
    pub destination_address: Ipv4Addr,
}

impl TryFrom<&[u8]> for Headers {
    type Error = PacketDecodeError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        let buf_size = buf.len();
        if buf_size < 20 || buf_size > 60 {
            return Err(PacketDecodeError::HeaderBufferSize(buf_size));
        }
        let headers = Self {
            ip_version: IpVersion::try_from(buf[0])?,
            header_length: buf[0] & 0x0F,
            type_of_service: TypeOfService::from(buf[1]),
            total_length: (buf[2] as u16) << 8 | buf[3] as u16,
            identifier: (buf[4] as u16) << 8 | buf[5] as u16,
            flags: Flags::from(buf[6]),
            fragment_offset: ((buf[6] as u16) << 8 | buf[7] as u16) & 0xD,
            ttl: buf[8],
            protocol: Protocol::try_from(buf[9])?,
            header_checksum: (buf[10] as u16) << 8 | buf[11] as u16,
            source_address: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
            destination_address: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
        };
        Ok(headers)
    }
}

#[derive(Debug)]
pub enum IpVersion {
    V4,
}

impl TryFrom<u8> for IpVersion {
    type Error = PacketDecodeError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte >> 4 {
            4 => Ok(IpVersion::V4),
            _ => Err(PacketDecodeError::UnknownIpVersion),
        }
    }
}

#[derive(Debug)]
pub struct TypeOfService {
    pub dscp: u8,
    pub ecn: u8,
}

impl From<u8> for TypeOfService {
    fn from(buf: u8) -> Self {
        Self {
            dscp: buf >> 2,
            ecn: buf & 0b11,
        }
    }
}

#[derive(Debug)]
pub struct Flags {
    pub df: bool,
    pub mf: bool,
}

impl From<u8> for Flags {
    fn from(buf: u8) -> Self {
        Self {
            df: if buf >> 6 & 0b1 == 0b1 { true } else { false },
            mf: if buf >> 5 & 0b1 == 0b1 { true } else { false },
        }
    }
}

#[derive(Debug)]
pub enum Protocol {
    ICMP,
    UDP,
    TCP,
}

impl TryFrom<u8> for Protocol {
    type Error = PacketDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Protocol::ICMP),
            6 => Ok(Protocol::TCP),
            17 => Ok(Protocol::UDP),
            _ => Err(PacketDecodeError::UnknownProtocol),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::error::PacketDecodeError;

    use super::{Flags, IpVersion, Protocol, TypeOfService};

    #[test]
    fn ipv4_when_byte_is_4() {
        let byte = 0x4F;
        let ip_version = IpVersion::try_from(byte);

        assert!(matches!(ip_version, Ok(IpVersion::V4)));
    }

    #[test]
    fn ipv4_when_byte_is_not_4() {
        let byte = 0xAF;
        let ip_version = IpVersion::try_from(byte);

        assert!(matches!(
            ip_version,
            Err(PacketDecodeError::UnknownIpVersion)
        ));
    }

    #[test]
    fn tos_from() {
        let byte = 0b1101;
        let tos = TypeOfService::from(byte);

        assert_eq!(tos.dscp, 0b11);
        assert_eq!(tos.ecn, 0b01);
    }

    #[test]
    fn flags_from() {
        let byte = 0b01100000;
        let flags = Flags::from(byte);

        assert_eq!(flags.df, true);
        assert_eq!(flags.mf, true);
    }

    #[test]
    fn protocol_when_byte_is_1() {
        let protocol = Protocol::try_from(1);

        assert!(matches!(protocol, Ok(Protocol::ICMP)));
    }

    #[test]
    fn protocol_when_byte_is_6() {
        let protocol = Protocol::try_from(6);

        assert!(matches!(protocol, Ok(Protocol::TCP)));
    }

    #[test]
    fn protocol_when_byte_is_17() {
        let protocol = Protocol::try_from(17);

        assert!(matches!(protocol, Ok(Protocol::UDP)));
    }

    #[test]
    fn protocol_when_byte_is_not_valid() {
        let protocol = Protocol::try_from(44);

        assert!(matches!(protocol, Err(PacketDecodeError::UnknownProtocol)));
    }
}
