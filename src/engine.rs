use std::{fs::File, io::Read, path::PathBuf};
use pnet::packet::ethernet::EthernetPacket;

use rlua::{Lua, Result, Context, Value};

pub mod types;
use types::*;

pub struct HarpyEngine {
    lua: Lua

}

impl HarpyEngine {
    pub fn empty() -> HarpyEngine {
        HarpyEngine {
            lua: Lua::new()
        }
    }
    pub fn new() -> HarpyEngine {
        let harpy = Self::empty();
        harpy.lua.context(|lua_ctx| {
            let g = lua_ctx.globals();
            g.set("harpy_version", env!("CARGO_PKG_VERSION")).unwrap();
            g.set("binary", lua_ctx.create_function::<(Value,), LuaBinary, _>(|_, (value,)| {
                // Iterate over the table and add all values to a Vec<u8>
                let mut buffer: Vec<u8> = Vec::new();

                match value {
                    Value::Table(table) => {
                        for v in table.pairs::<Value, Value>() {
                            let (_, value) = v.unwrap();
                            match value {
                                Value::String(s) => {
                                    let bytes = s.as_bytes();
                                    buffer.extend_from_slice(bytes);
                                },
                                Value::Integer(n) => {
                                    if n <= 255{
                                        buffer.push(n as u8);
                                    }else{
                                        for byte in n.to_ne_bytes() {
                                            buffer.push(byte);
                                        }
                                    }
                                },
                                _ => { }
                            }
                        }
                    },
                    Value::String(string) => {
                        let bytes = string.as_bytes();
                        buffer.extend_from_slice(bytes);
                    },
                    _ => {}
                }
                Ok(LuaBinary(buffer))
            }).unwrap()).unwrap();
            g.set("binary_to_string", lua_ctx.create_function::<(Value,), String, _>(|_, (value,)| {
                let mut buffer: Vec<u8> = Vec::new();
                match value {
                    Value::UserData(d)
                        if d.is::<LuaBinary>() => {
                        let user_data = d.borrow::<LuaBinary>().unwrap();
                        buffer.extend_from_slice(user_data.0.as_slice());
                    }
                    _ => { }
                }
                Ok(unsafe { String::from_utf8_unchecked(buffer) })
            }).unwrap()).unwrap();

        });
        harpy
    }
    pub fn context<F, R>(&self, f: F) -> R where F: FnOnce(Context<'_>) -> R {
        self.lua.context(|lua_ctx| {
            f(lua_ctx)
        })
    }
    pub fn run_file(&self, file: PathBuf) -> Result<()> {
        let mut file = File::open(file).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        self.lua.context(|lua_ctx| {
            lua_ctx.load(&contents).exec()?;
            Ok(())
        })
    }
}

#[derive(PartialEq)]
pub enum EngineResult {
    Continue,
    Drop,
    Tamper(EthernetPacket<'static>)
}
