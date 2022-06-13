use pnet::datalink::NetworkInterface;
use std::{net::{IpAddr, Ipv4Addr}, fs::File, io::{BufReader, BufRead}};


pub fn get_gateway_for(interface: &NetworkInterface) -> Option<IpAddr> {
    // Read /proc/net/route to get the gateway for the given interface
    // The format of this file is:
    // Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
    // Every field is delimited by a tabular space.
    // Loop over every line after the first, and get `Iface`, compare it to the given interface,
    // and if it matches, get the `Gateway` field.
    // If the `Gateway` field is not `00000000`, return it as an `IpAddress`.
    // If the `Gateway` field is `00000000`, return `None`.
    let mut gateway: Option<IpAddr> = None;
    let file = File::open("/proc/net/route").unwrap();
    let mut lines = BufReader::new(file).lines();
    lines.next();
    for line in lines {
        let line = line.unwrap();
        let parts: Vec<&str> = line.split('\t').collect();
        if parts[0] == interface.name {
            let gateway_str = parts[2];
            if gateway_str != "00000000" {
                // Convert "binary form" aabbccdd where each pair is the hexadecimal representation
                // of a byte into a ip-address in decimal format
                let gateway_raw = u32::from_str_radix(gateway_str, 16).unwrap().to_be();
                gateway = Some(IpAddr::V4(Ipv4Addr::from(gateway_raw)));
            }
        }
    }
    gateway
}


#[inline]
pub fn checksum(octets: &[u8]) -> u16 {
    // Calculate the checksum compliant with RFC 1071
    // https://tools.ietf.org/html/rfc1071
    //
    // I couldn't get the code from the RFC to work, so I looked around a bit and found a similar
    // algorithm for C on stackoverflow. After porting it to rust, it does seem to work.
    // Yes, this uses unsafe, but I can't see any way this could ever result in a segfault.
    // All below used "unsafe" code, is inherently safe due to bounds checking, thus, unless
    // someone comes up with a safe, faster way to calculate the checksum, this will stay as is.
    // 
    unsafe {
        let mut sum: u32 = 0xffff;
        let mut addr: *const u16 = octets.as_ptr() as *const u16;
        let mut len = octets.len();
        while len > 1 {
            sum += *addr as u32;
            addr = addr.add(1);
            len -= 2;
            if sum > 0xffff {
                sum -= 0xffff;
            }
        }

        if len > 0 {
            sum += *addr as u32;
            if sum > 0xffff {
                sum -= 0xffff;
            }
        }

        (!sum as u16).to_be()
    }
}

pub trait Subsequence<O> {
    fn subsequence(&self, other: O) -> bool;
}

impl<'a, T, O: AsRef<&'a [T]>> Subsequence<O> for Vec<T>
where T: PartialEq + 'a {
    fn subsequence(&self, other: O) -> bool
    where T: 'a {
        let slice = self.as_slice();
        let other = other.as_ref();
        for i in 0..(self.len() - other.len()) {
            if slice[i..i+other.len()] == other[..] {
                return true;
            }
        }
        false
    }
}

impl<'a, T, O: Iterator<Item = &'a T>> Subsequence<O> for std::slice::Iter<'_, T>
where T: PartialEq + Clone + 'a {
    fn subsequence(&self, other: O) -> bool {
        let slice = self.as_slice();
        let other = other.cloned().collect::<Vec<T>>();
        for i in 0..(self.len() - other.len()) {
            if &slice[i..i+other.len()] == &other[..] {
                return true;
            }
        }
        false
    }
}


#[test]
fn test_subsequence() {
    use hex_literal::hex;
    // Uses a DNS response to check for a domain name in the raw response
    let response = hex!("484efc9d1a60e0d55eac1f1b080045000051b7100000401100bcc0a8002601010101c35c0035003dc31ecdfd012000010000000000010832376a757374696e03646576000001000100002904d000000000000c000a0008b16ef21ad93bdc8c");

    let response_iter = response.iter();
    assert_eq!(response_iter.subsequence(&mut b"27justin".iter()), true);
    assert_eq!(response_iter.subsequence(&mut b"not there".iter()), false);
}

#[test]
fn test_checksum() {
    use hex_literal::hex;
    let ip_header = hex!("4500003c7b35400040060000c0a800260d20384b");
    assert_eq!(checksum(&ip_header), 0xb94d);
}

