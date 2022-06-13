use super::*;

pub struct LuaIpv4Packet(pub Ipv4Packet<'static>);

impl UserData for LuaIpv4Packet {
    fn add_methods<'lua, T: UserDataMethods<'lua, Self>>(_methods: &mut T) {
        _methods.add_method("src", |_, this: &LuaIpv4Packet, ()| {
            Ok(this.0.get_source().to_string())
        });
        _methods.add_method("dst", |_, this: &LuaIpv4Packet, ()| {
            Ok(this.0.get_destination().to_string())
        });
        _methods.add_method("protocol", |_, this: &LuaIpv4Packet, ()| {
            Ok(this.0.get_next_level_protocol().to_string())
        });
        _methods.add_method("size", |_, this: &LuaIpv4Packet, ()| {
            Ok(this.0.packet().len())
        });
        _methods.add_method("tcp", |_, this: &LuaIpv4Packet, ()| {
            Ok(this.as_tcp())
        });
        _methods.add_method("udp", |_, this: &LuaIpv4Packet, ()| {
            Ok(this.as_udp())
        });
        _methods.add_method_mut::<_, (Option<AnyUserData>,), _, _>("payload", |_, this: &mut LuaIpv4Packet, (data,)| {
            struct PseudoHeader {
                saddr: u32,
                daddr: u32,
                zero: u8,
                protocol: u8,
                length: u16,
            }
            fn make_checksum(phd: PseudoHeader, data: &[u8]) -> u16 {
                let mut buf = Vec::with_capacity(std::mem::size_of::<PseudoHeader>() + data.len());
                buf.resize(buf.capacity(), 0);
                buf[0..4].copy_from_slice(&phd.saddr.to_be_bytes());
                buf[4..8].copy_from_slice(&phd.daddr.to_be_bytes());
                buf[8] = phd.zero;
                buf[9] = phd.protocol;
                buf[10..12].copy_from_slice(&phd.length.to_be_bytes());
                buf.extend_from_slice(&data[..]);
                crate::util::checksum(&buf)
            }

            if let Some(data) = data {
                if data.is::<LuaTcpPacket>() {
                    let tcp = data.borrow::<LuaTcpPacket>()?;
                    let packet = tcp.0.packet();

                    let bsize = Ipv4Packet::minimum_packet_size() + packet.len();
                    let mut buf = Vec::with_capacity(bsize);
                    buf.extend(&this.0.packet()[0..(this.0.packet().len() - this.0.payload().len())]);
                    buf.resize(bsize, 0);

                    let mut ipv4 = MutableIpv4Packet::owned(buf).unwrap();
                    ipv4.set_total_length(((this.0.packet().len() - this.0.payload().len()) + tcp.0.packet().len()) as u16);
                    ipv4.set_payload(packet);
                    ipv4.set_checksum(0);
                    ipv4.set_checksum(crate::util::checksum(&ipv4.packet()[0..(ipv4.packet().len() - ipv4.payload().len())]));
                    // Calculate TCP checksum
                    let pseudo = PseudoHeader {
                        saddr: this.0.get_source().into(),
                        daddr: this.0.get_destination().into(),
                        zero: 0,
                        protocol: IpNextHeaderProtocols::Tcp.0,
                        length: tcp.0.packet().len() as u16,
                    };

                    let mut tcp = MutableTcpPacket::owned(ipv4.payload().to_vec()).unwrap();
                    tcp.set_checksum(0);
                    // Connect pseudo header and TCP packet together into one slice
                    // and calculate checksum
                    tcp.set_checksum(make_checksum(pseudo, tcp.packet()));
                    ipv4.set_payload(tcp.packet());

                    this.0 = ipv4.consume_to_immutable();
                    return Ok(None);
                }else if data.is::<LuaUdpPacket>() {
                    let udp = data.borrow::<LuaUdpPacket>()?;
                    let packet = udp.0.packet();

                    let bsize = Ipv4Packet::minimum_packet_size() + packet.len();
                    let mut buf = Vec::with_capacity(bsize);
                    buf.extend(&this.0.packet()[0..(this.0.packet().len() - this.0.payload().len())]);
                    buf.resize(bsize, 0);

                    let mut ipv4 = MutableIpv4Packet::owned(buf).unwrap();
                    ipv4.set_total_length(((this.0.packet().len() - this.0.payload().len()) + udp.0.packet().len()) as u16);
                    ipv4.set_checksum(0);
                    ipv4.set_checksum(crate::util::checksum(&ipv4.packet()[0..(ipv4.packet().len() - ipv4.payload().len())]));
                    // Calculate TCP checksum
                    let _pseudo = PseudoHeader {
                        saddr: this.0.get_source().into(),
                        daddr: this.0.get_destination().into(),
                        zero: 0,
                        protocol: IpNextHeaderProtocols::Udp.0,
                        length: packet.len() as u16,
                    };

                    let mut udp = MutableUdpPacket::owned(packet.to_vec()).unwrap();
                    udp.set_checksum(0);
                    // TODO: Calculate UDP checksum
                    // The current make_checksum function, weirdly enough, works for TCP, but not UDP
                    // why that is, I don't know. Since both protocols use the same checksum
                    // algorithm, I deduce that this issue might stem from the UDP data itself.
                    // However since UDP does not require checksums, I'll leave the checksum at 0
                    // for now.
                    //udp.set_checksum(make_checksum(pseudo, udp.packet()));
                    ipv4.set_payload(udp.packet());

                    this.0 = ipv4.consume_to_immutable();
                    return Ok(None);
                }else if data.is::<LuaBinary>() {
                    let bin = data.borrow::<LuaBinary>()?;

                    let bsize = Ipv4Packet::minimum_packet_size() + bin.0.len();
                    let mut buf = Vec::with_capacity(bsize);
                    buf.extend(&this.0.packet()[0..(this.0.packet().len() - this.0.payload().len())]);
                    buf.resize(bsize, 0);

                    let mut ipv4 = MutableIpv4Packet::owned(buf).unwrap();
                    ipv4.set_total_length(((this.0.packet().len() - this.0.payload().len()) + bin.0.len()) as u16);
                    ipv4.set_payload(&bin.0);
                    ipv4.set_checksum(0);
                    ipv4.set_checksum(crate::util::checksum(&ipv4.packet()[0..(ipv4.packet().len() - ipv4.payload().len())]));
                    this.0 = ipv4.consume_to_immutable();
                    return Ok(None);
                }
            }
            Ok(Some(LuaBinary(this.0.packet().to_vec())))
        });
    }
    fn get_uvalues_count(&self) -> std::os::raw::c_int {
        1
    }
}
impl LuaIpv4Packet {
    pub fn as_tcp(&self) -> Option<LuaTcpPacket> {
        if self.0.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
            Some(LuaTcpPacket(TcpPacket::owned(self.0.payload().to_vec()).unwrap()))
        } else {
            None
        }
    }
    pub fn as_udp(&self) -> Option<LuaUdpPacket> {
        if self.0.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            Some(LuaUdpPacket(UdpPacket::owned(self.0.payload().to_vec()).unwrap()))
        } else {
            None
        }
    }
}
