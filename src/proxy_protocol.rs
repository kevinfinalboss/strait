//! PROXY protocol header, so backends see the client's address.
//!
//! A proxy opens its own connection to the backend, so the backend sees the
//! proxy's address as the peer. With the PROXY protocol, the proxy sends a
//! short header first that carries the original client and listener
//! addresses; HAProxy, nginx, Envoy and most load-balancer-aware servers read
//! it. strait sends version 2, the binary form, defined in
//! <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>.

use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

/// Which PROXY protocol header a listener sends to its backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyProtocol {
    /// Version 2, binary.
    V2,
}

/// Every v2 header starts with these 12 bytes.
const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Version 2, command PROXY: the connection was relayed for a client.
const VERSION_PROXY: u8 = 0x21;
const TCP_OVER_IPV4: u8 = 0x11;
const TCP_OVER_IPV6: u8 = 0x21;

/// The v2 header for a TCP connection from `client` to `listener`, the
/// address the client connected to.
///
/// Both addresses must be of one family. IPv4 clients of a dual-stack listener
/// show up as IPv4-mapped IPv6 addresses; they are sent as plain IPv4, which
/// is what the backend would have seen without a proxy.
pub fn header_v2(client: SocketAddr, listener: SocketAddr) -> Vec<u8> {
    let (src, dst) = (client.ip().to_canonical(), listener.ip().to_canonical());
    let mut header = Vec::with_capacity(16 + 36);
    header.extend_from_slice(&SIGNATURE);
    header.push(VERSION_PROXY);
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            header.push(TCP_OVER_IPV4);
            header.extend_from_slice(&12u16.to_be_bytes());
            header.extend_from_slice(&src.octets());
            header.extend_from_slice(&dst.octets());
        }
        // One side IPv4 and the other IPv6 cannot happen on one socket, but
        // if it did, the mapped form keeps both addresses intact.
        _ => {
            let v6 = |ip: IpAddr| match ip {
                IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                IpAddr::V6(ip) => ip,
            };
            header.push(TCP_OVER_IPV6);
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&v6(src).octets());
            header.extend_from_slice(&v6(dst).octets());
        }
    }
    header.extend_from_slice(&client.port().to_be_bytes());
    header.extend_from_slice(&listener.port().to_be_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn encodes_ipv4() {
        let header = header_v2(addr("192.0.2.10:51234"), addr("10.0.0.1:443"));
        let mut expected = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        expected.extend_from_slice(&[0x21, 0x11, 0, 12]);
        expected.extend_from_slice(&[192, 0, 2, 10, 10, 0, 0, 1]);
        expected.extend_from_slice(&[0xc8, 0x22, 0x01, 0xbb]); // 51234, 443
        assert_eq!(header, expected);
    }

    #[test]
    fn encodes_ipv6() {
        let header = header_v2(addr("[2001:db8::10]:51234"), addr("[2001:db8::1]:443"));
        assert_eq!(header.len(), 16 + 36);
        assert_eq!(&header[12..16], &[0x21, 0x21, 0, 36]);
        assert_eq!(
            &header[16..32],
            &"2001:db8::10"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(
            &header[32..48],
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(&header[48..], &[0xc8, 0x22, 0x01, 0xbb]);
    }

    #[test]
    fn sends_ipv4_clients_of_a_dual_stack_listener_as_ipv4() {
        let header = header_v2(
            addr("[::ffff:192.0.2.10]:51234"),
            addr("[::ffff:10.0.0.1]:443"),
        );
        assert_eq!(
            header,
            header_v2(addr("192.0.2.10:51234"), addr("10.0.0.1:443"))
        );
    }
}
