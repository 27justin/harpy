use super::*;
use crate::tls::TlsPacket;

pub struct LuaTcpPacket(pub TcpPacket<'static>);

impl LuaTcpPacket {
    /// Check whether the packet contains TLS data
    pub fn is_tls(&self) -> bool {
        let payload = self.0.payload();
        payload.len() >= 2
            && (payload[0] == 0x16 || payload[0] == 0x17)
            && payload[1] == 0x03
    }
    pub fn as_tls(&self) -> Option<LuaTls> {
        if self.is_tls() {
            Some(LuaTls(TlsPacket::owned(self.0.payload().to_vec())?))
        } else {
            None
        }
    }
}
impl UserData for LuaTcpPacket {
    fn add_methods<'lua, T: UserDataMethods<'lua, Self>>(_methods: &mut T) {
        _methods.add_method("src_port", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.get_source())
        });
        _methods.add_method("dst_port", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.get_destination())
        });
        _methods.add_method("size", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.packet().len())
        });
        _methods.add_method("seq", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.get_sequence())
        });
        _methods.add_method("ack", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.get_acknowledgement())
        });
        _methods.add_method("flags", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.get_flags())
        });
        _methods.add_method("window", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.get_window())
        });
        _methods.add_method("checksum", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.get_checksum().to_string())
        });
        _methods.add_method("urgent", |_, this: &LuaTcpPacket, ()| {
            Ok(this.0.get_urgent_ptr().to_string())
        });
        _methods.add_method("is_tls", |_, this: &LuaTcpPacket, ()| {
            Ok(this.is_tls())
        });
        _methods.add_method("tls", |_, this: &LuaTcpPacket, ()| {
            Ok(this.as_tls())
        });
        _methods.add_method_mut::<_, (Option<Value>,), _, _>("payload", |_, this: &mut LuaTcpPacket, (binary,)| {
            if let Some(binary) = binary {
                match binary {
                    Value::UserData(d) => {
                        if let Ok(data) = d.borrow::<LuaBinary>() {
                            let tcp_header = &this.0.packet()[0..(this.0.packet().len() - this.0.payload().len())];
                            let bsize = tcp_header.len() + data.0.len();
                            let mut buf = Vec::with_capacity(bsize);
                            buf.extend(tcp_header);
                            buf.resize(bsize, 0);

                            let mut tcp = MutableTcpPacket::owned(buf).unwrap();
                            tcp.set_payload(&data.0);
                            this.0 = tcp.consume_to_immutable();
                            Ok(None)
                        } else {
                            Ok(None)
                        }
                    },
                    Value::Table(binary) => {
                        let mut payload: Vec<u8> = binary.pairs::<Value, u8>().into_iter().map(|pair| pair.map(|p| p.1).unwrap_or(0)).collect::<Vec<u8>>();

                        let tcp_header = &this.0.packet()[0..(this.0.packet().len() - this.0.payload().len())];
                        let bsize = tcp_header.len() + payload.len();
                        let mut buf = Vec::with_capacity(bsize);
                        buf.extend(tcp_header);
                        buf.resize(bsize, 0);

                        let mut tcp = MutableTcpPacket::owned(buf).unwrap();
                        tcp.set_payload(&mut payload);


                        // NOTE: we can't compute the checksum here because we don't know the IP header which
                        // TCP requires to compute a correct checksum, therefore LuaIpv4Packet's payload
                        // function calculates the TCP checksum
                        this.0 = tcp.consume_to_immutable();
                        Ok(None)
                    },
                    _ => { Ok(None) }
                }
            }else{
                Ok(Some(LuaBinary(this.0.payload().to_vec())))
            }
        });
    }

    fn get_uvalues_count(&self) -> std::os::raw::c_int {
        1
    }
}
