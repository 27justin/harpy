use super::*;
use crate::quic::QUICPacket;

pub struct LuaUdpPacket(pub UdpPacket<'static>);

impl LuaUdpPacket {

    pub fn is_quic(&self) -> bool {
        // Get the payload and check the first 2 MS bits of the first byte
        // if both are 1, then it's a QUIC packet
        // TODO: this only returns true for QUIC long headers, not for QUIC short headers
        //       this should be fixed, but for now this suffices
        let payload = self.0.payload();
        payload.len() > 0 && (payload[0] & 0xC0 == 0xC0)
    }
}
impl UserData for LuaUdpPacket {
    fn add_methods<'lua, T: UserDataMethods<'lua, Self>>(_methods: &mut T) {
        _methods.add_method("src_port", |_, this: &LuaUdpPacket, ()| {
            Ok(this.0.get_source())
        });
        _methods.add_method("dst_port", |_, this: &LuaUdpPacket, ()| {
            Ok(this.0.get_destination())
        });
        _methods.add_method("size", |_, this: &LuaUdpPacket, ()| {
            Ok(this.0.packet().len())
        });
        _methods.add_method("checksum", |_, this: &LuaUdpPacket, ()| {
            Ok(this.0.get_checksum().to_string())
        });
        _methods.add_method_mut::<_, (Option<Value>,), _, _>("payload", |_, this: &mut LuaUdpPacket, (binary,)| {
            if let Some(binary) = binary {
                match binary {
                    Value::UserData(d) if d.is::<LuaBinary>() => {
                        let data = d.borrow::<LuaBinary>().unwrap();
                        let mut payload = data.0.clone();

                        let udp_header = &this.0.packet()[0..(this.0.packet().len() - this.0.payload().len())];
                        let bsize = udp_header.len() + payload.len();
                        let mut buf = Vec::with_capacity(bsize);
                        buf.extend(udp_header);
                        buf.resize(bsize, 0);

                        let mut udp = MutableUdpPacket::owned(buf).unwrap();
                        udp.set_payload(&mut payload);
                        udp.set_length((8 + payload.len()) as u16);
                        udp.set_checksum(0);

                        // NOTE: we can't compute the checksum here because we don't know the IP header which
                        // UDP requires to compute a correct checksum, therefore LuaIpv4Packet's payload
                        // function calculates the UDP checksum
                        this.0 = udp.consume_to_immutable();
                    },
                    _ => { error!("This type is not applicable to LuaUdpPacket:payload()"); }
                }
                Ok(None)
            }else{
                Ok(Some(LuaBinary(this.0.payload().to_vec())))
            }
        });
        _methods.add_method("is_quic", |_, this: &LuaUdpPacket, ()| {
            Ok(this.is_quic())
        });
        _methods.add_method("quic", |_, this: &LuaUdpPacket, ()| {
            if this.is_quic() {
                let payload = this.0.payload();
                // Match the QUIC packet type
                // It is stored in the 2-4 bits of the first byte
                // 0x00: initial
                // 0x01: 0-RTT
                // 0x02: Handshake
                // 0x03: Retry
                let packet_type = payload[0] & 0x3;
                match packet_type {
                    0x00 => return Ok(Some(LuaQUIC(QUICPacket::owned(payload.to_vec()).unwrap()))),
                    0x01 => return Ok(None),
                    0x02 => return Ok(None),
                    0x03 => return Ok(None),
                    _ => return Err(LuaError::external("Invalid QUIC packet type"))
                }
            }
            Ok(None)
        });
    }

    fn get_uvalues_count(&self) -> std::os::raw::c_int {
        1
    }
}

