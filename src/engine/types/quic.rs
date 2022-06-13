use super::*;
pub use crate::quic::QUICPacket;

pub struct LuaQUIC(pub QUICPacket<'static>);


impl UserData for LuaQUIC {
    fn add_methods<'lua, T: UserDataMethods<'lua, Self>>(_methods: &mut T) {
        _methods.add_method("version", |_, this: &LuaQUIC, ()| {
            Ok(this.0.get_version().to_string())
        });
        _methods.add_method("destination_cid", |_, this: &LuaQUIC, ()| {
            Ok(String::from_utf8(this.0.get_dst_connection_id().to_vec()).unwrap_or("".to_string()))
        });
        _methods.add_method("source_cid", |_, this: &LuaQUIC, ()| {
            Ok(String::from_utf8(this.0.get_src_connection_id().to_vec()).unwrap_or("".to_string()))
        });
        /*_methods.add_method("token", |_, this: &LuaQUIC, ()| {
            Ok(String::from_utf8(this.0.get_token().to_vec()).unwrap_or("".to_string()))
        });*/
    }

    fn get_uvalues_count(&self) -> std::os::raw::c_int {
        1
    }
}
