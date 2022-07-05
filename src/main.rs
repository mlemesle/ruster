use std::net::UdpSocket;

use packet::Packet;

mod packet;
mod packet_data;

mod error;

pub const MTU: usize = 1500;

fn main() {
    let socket = UdpSocket::bind("127.0.0.1:4444").expect("Couldn't bind to socket");
    let mut buf = [0u8; MTU];
    socket
        .recv(&mut buf)
        .expect("Error while reading incoming packets");

    let packet = Packet::<String>::try_from(&buf);
    println!("{:?}", packet);
}
