use super::*;

pub struct LuaBinary(pub Vec<u8>);


impl UserData for LuaBinary {
    fn add_methods<'lua, T: UserDataMethods<'lua, Self>>(_methods: &mut T) {
        _methods.add_method("len", |_, this: &LuaBinary, ()| {
            Ok(this.0.len() as u32)
        });
        _methods.add_method::<_, (usize,), Option<u8>, _>("get", |_, this: &LuaBinary, (index,)| {
            if index < this.0.len() {
                Ok(Some(this.0[index]))
            } else {
                Ok(None)
            }
        });
        _methods.add_method::<_, (Value,), _, _>("contains", |_, this: &LuaBinary, (search,)| {
            // Check if the binary contains the given value
            // The given value can be a string, a table, or another userdata (LuaBinary)
            match search {
                Value::UserData(d) if d.is::<LuaBinary>() => {
                    let data = d.borrow::<LuaBinary>().unwrap();
                    return Ok(this.0.iter().subsequence(&mut data.0.iter()));
                },
                Value::String(s) => {
                    let bytes = s.as_bytes();
                    return Ok(this.0.iter().subsequence(&mut bytes.iter()));
                },
                Value::Table(table) => {
                    let v = table.pairs::<Value, u8>().map(|r| r.unwrap().1).collect::<Vec<u8>>();
                    return Ok(this.0.iter().subsequence(&mut v.iter()));
                },
                _ => return Ok(false)
            }
        });

    }

    fn get_uvalues_count(&self) -> std::os::raw::c_int {
        1
    }
}
