use super::*;
use crate::tls::TlsPacket;

pub struct LuaTls(pub TlsPacket<'static>);
pub struct LuaClientHello {
    pub sni: Option<String>,
    pub ciphersuites: Vec<rustls::CipherSuite>,
    pub signature_schemes: Vec<rustls::SignatureScheme>
}

impl LuaTls {
    pub fn as_client_hello(&self) -> Option<LuaClientHello> {
        if self.0.get_content_type() == 0x16 {
            let mut acceptor = rustls::server::Acceptor::new().unwrap();
            let mut p = self.0.packet();
            if let Ok(_) = acceptor.read_tls(&mut p) {
                if let Ok(Some(hello)) = acceptor.accept() {
                    let hello = hello.client_hello();
                    return Some(LuaClientHello {
                        sni: hello.server_name().clone().map(ToOwned::to_owned),
                        ciphersuites: hello.cipher_suites().to_vec(),
                        signature_schemes: hello.signature_schemes().to_vec()
                    });

                }
            }
        }
        None
    }
}

impl UserData for LuaTls {
    fn add_methods<'lua, T: UserDataMethods<'lua, Self>>(_methods: &mut T) {
        _methods.add_method("version", |_, this: &LuaTls, ()| {
            Ok(match this.0.get_version() {
                0x0303 => "TLS 1.3",
                0x0302 => "TLS 1.2",
                0x0301 => "TLS 1.1",
                0x0300 => "TLS 1.0",
                0x0201 => "SSL 3.0",
                0x0202 => "SSL 2.0",
                _ => "Unknown"
            }.to_string())
        });
        _methods.add_method("content_type", |_, this: &LuaTls, ()| {
            Ok(this.0.get_content_type().to_string())
        });
        _methods.add_method("size", |_, this: &LuaTls, ()| {
            Ok(this.0.payload().len())
        });
        _methods.add_method("client_hello", |_, this: &LuaTls, ()| {
            Ok(this.as_client_hello())
        });
    }

    fn get_uvalues_count(&self) -> std::os::raw::c_int {
        1
    }
}

impl UserData for LuaClientHello {
    fn add_methods<'lua, T: UserDataMethods<'lua, Self>>(_methods: &mut T) {
        _methods.add_method("sni", |_, this: &LuaClientHello, ()| {
            Ok(this.sni.clone())
        });
        _methods.add_method("ciphersuites", |_, this: &LuaClientHello, ()| {
            Ok(this.ciphersuites.iter().map(|c| c.as_str().map(ToOwned::to_owned).unwrap_or("".to_owned())).collect::<Vec<String>>())
        });
        _methods.add_method("signature_schemes", |_, this: &LuaClientHello, ()| {
            Ok(this.signature_schemes.iter().map(|c| c.as_str().map(ToOwned::to_owned).unwrap_or("".to_owned())).collect::<Vec<String>>())
        });
    }
}
