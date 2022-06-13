use super::*;

pub struct LuaEthernetPacket(pub EthernetPacket<'static>, pub bool, pub bool);

impl<'a> From<&'a EthernetPacket<'static>> for LuaEthernetPacket {
    fn from(packet: &'a EthernetPacket<'static>) -> Self {
        LuaEthernetPacket(EthernetPacket::owned(packet.packet().to_vec()).unwrap(), false, false)
    }
}

impl LuaEthernetPacket {
    pub fn new(packet: EthernetPacket<'static>) -> Self {
        LuaEthernetPacket(packet, false, false)
    }
    pub fn dropped(&self) -> bool {
        self.1
    }
    pub fn tampered(&self) -> bool {
        self.2
    }
    pub fn as_ipv4(&self) -> Option<LuaIpv4Packet> {
        if self.0.get_ethertype() == EtherTypes::Ipv4 {
            Some(LuaIpv4Packet(Ipv4Packet::owned(self.0.payload().to_vec()).unwrap()))
        } else {
            None
        }
    }
}

impl Clone for LuaEthernetPacket {
    fn clone(&self) -> Self {
        LuaEthernetPacket(EthernetPacket::owned(self.0.packet().to_vec()).unwrap(), self.1, self.2)
    }
}

impl UserData for LuaEthernetPacket {
    fn add_methods<'lua, T: UserDataMethods<'lua, Self>>(_methods: &mut T) {
        _methods.add_method("ipv4", |_, this: &LuaEthernetPacket, ()| {
            Ok(this.as_ipv4())
        });
        _methods.add_method("src", |_, this: &LuaEthernetPacket, ()| {
            Ok(this.0.get_source().to_string())
        });
        _methods.add_method("dst", |_, this: &LuaEthernetPacket, ()| {
            Ok(this.0.get_destination().to_string())
        });
        _methods.add_method("type", |_, this: &LuaEthernetPacket, ()| {
            Ok(this.0.get_ethertype().to_string())
        });
        _methods.add_method("size", |_, this: &LuaEthernetPacket, ()| {
            Ok(this.0.packet().len())
        });
        _methods.add_method_mut("drop", |_, this: &mut LuaEthernetPacket, ()| {
            this.1 = true;
            Ok(())
        });
        _methods.add_method("is_dropped", |_, this: &LuaEthernetPacket, ()| {
            Ok(this.1)
        });
        _methods.add_method_mut::<_, (AnyUserData,), _, _>("payload", |_, this: &mut LuaEthernetPacket, (data,)| {
            if data.is::<LuaIpv4Packet>() {
                let ipv4 = data.borrow::<LuaIpv4Packet>()?;
                let packet = ipv4.0.packet();
                let bsize = EthernetPacket::minimum_packet_size() + packet.len();
                let mut buf = Vec::with_capacity(bsize);

                buf.extend(&this.0.packet()[0..(this.0.packet().len() - this.0.payload().len())]);
                buf.resize(bsize, 0);

                let mut eth = MutableEthernetPacket::owned(buf).unwrap();
                eth.set_payload(packet);

                this.0 = eth.consume_to_immutable();
                this.2 = true;
                return Ok(None);
            }else{
                return Ok(Some(LuaBinary(this.0.payload().to_vec())));
            }
        });

    }
    fn get_uvalues_count(&self) -> std::os::raw::c_int {
        1
    }
}
impl Into<EthernetPacket<'static>> for LuaEthernetPacket {
    fn into(self) -> EthernetPacket<'static> {
        self.0
    }
}
