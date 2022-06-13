use pnet_macros::packet;
use pnet_macros_support::types::*;

pub trait FromBinary
    where Self: Sized {
    type Error;
    fn from_binary(bytes: &[u8]) -> Result<Self, Self::Error>;
}
// Waiting for generic_const_exprs to be stable, once it is this code can be improved by allocating
// an array instead of a vector and resizing it
impl<T: Copy> FromBinary for T {
    type Error = ();
    fn from_binary(bytes: &[u8]) -> Result<T, ()> {
        if bytes.len() != std::mem::size_of::<T>() {
            return Err(());
        }
        let mut buf = Vec::with_capacity(std::mem::size_of::<T>());
        buf.extend_from_slice(bytes);
        Ok(unsafe { *(buf.as_ptr() as *const T) })
    }
}


#[packet]
pub struct QUIC {
    pub header_form: u1,
    pub fixed_bit: u1,
    pub packet_type: u2,
    pub reserved: u2,
    pub packet_num_len: u2,

    pub version: u32be,
    pub dst_connection_id_len: u8,
    #[length = "dst_connection_id_len"]
    pub dst_connection_id: Vec<u8>,

    pub src_connection_id_len: u8,
    #[length = "src_connection_id_len"]
    pub src_connection_id: Vec<u8>,
    #[payload]
    pub payload: Vec<u8>
}


#[derive(Debug, Clone, PartialEq)]
pub struct Initial {
    pub token_len: QUICInteger,
    pub token: Vec<u8>,
    pub length: QUICInteger,
    pub packet_num: QUICInteger,
    pub payload: Vec<u8>
}
impl FromBinary for Initial {
    type Error = ();
    fn from_binary(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 2 {
            return Err(());
        }
        let mut addr = 0;
        let token_len = QUICInteger::try_from(&bytes[0..std::cmp::min(bytes.len(), 4)])?;
        addr += token_len.length as usize;

        let token = &bytes[ token_len.length as usize .. std::cmp::max(token_len.value as usize, token_len.length as usize )];
        addr += token.len();

        let length = QUICInteger::try_from(&bytes[addr..std::cmp::min(bytes.len(), addr + 4)])?;
        addr += length.length as usize;

        let packet_num = QUICInteger::try_from(&bytes[addr..std::cmp::min(bytes.len(), addr + 4)])?;
        addr += packet_num.length as usize;
        let payload = &bytes[addr..];

        Ok(Self {
            token_len,
            token: token.to_vec(),
            length,
            packet_num,
            payload: payload.to_vec()
        })
    }
}

pub const fn get_quic_salt(version: u32be) -> [u8; 20]{
    match version {
        // VERSION 1
        0x1 => [ 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a ],
        // DRAFT 29
        0xff00001d => [ 0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99 ],
        // DRAFT 27 & 28
        0xff00001b
        | 0xff00_001c => [ 0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02 ],
        _ => unimplemented!()
    }
}


// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-4.1
#[derive(Debug, PartialEq, Clone)]
pub struct QUICInteger {
    pub length: u8,
    pub value: u64be
}
impl QUICInteger {
    pub const fn max_length() -> u8 {
        8
    }
}
// Implement conversion traits and function to easily convert between QUICInteger and u8-u64
impl From<u8> for QUICInteger {
    fn from(value: u8) -> Self {
        Self {
            length: 1,
            value: value.into()
        }
    }
}
impl From<u16> for QUICInteger {
    fn from(value: u16) -> Self {
        Self {
            length: 2,
            value: value.into()
        }
    }
}
impl From<u32> for QUICInteger {
    fn from(value: u32) -> Self {
        Self {
            length: 4,
            value: value.into()
        }
    }
}
impl From<u64> for QUICInteger {
    fn from(value: u64) -> Self {
        Self {
            length: 8,
            value
        }
    }
}
impl TryFrom<QUICInteger> for u8 {
    type Error = ();

    fn try_from(value: QUICInteger) -> Result<Self, Self::Error> {
        if value.length != 1 {
            Err(())
        } else {
            Ok(value.value.try_into().unwrap())
        }
    }
}
impl TryFrom<QUICInteger> for u16 {
    type Error = ();

    fn try_from(value: QUICInteger) -> Result<Self, Self::Error> {
        if value.length > 2 {
            Err(())
        } else {
            Ok(value.value.try_into().unwrap())
        }
    }
}
impl TryFrom<QUICInteger> for u32 {
    type Error = ();

    fn try_from(value: QUICInteger) -> Result<Self, Self::Error> {
        if value.length > 4 {
            Err(())
        } else {
            Ok(value.value.try_into().unwrap())
        }
    }
}
impl TryFrom<QUICInteger> for u64 {
    type Error = ();

    fn try_from(value: QUICInteger) -> Result<Self, Self::Error> {
        if value.length > 8 {
            Err(())
        } else {
            Ok(value.value)
        }
    }
}

impl TryFrom<&[u8]> for QUICInteger {
    type Error = ();
    fn try_from(octets: &[u8]) -> Result<Self, Self::Error> {
        if octets.len() == 0 {
            return Err(());
        }
        // Check the two MSB bits of the first byte to determine the length
        let length: u8 = match octets[0] >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unimplemented!()
        };
        let mut value: u64 = 0;
        // Remove the two MSB bits of the first byte and add the remaining bits to the value
        value |= (octets[0] & 0x3F) as u64;
        for i in 1..length {
            value <<= 8;
            value |= octets[i as usize] as u64;
        }
        Ok(Self {
            length,
            value
        })
    }
}
impl<const N: usize> TryFrom<&[u8; N]> for QUICInteger {
    type Error = ();

    fn try_from(octets: &[u8; N]) -> Result<Self, Self::Error> {
        if octets.len() == 0 {
            return Err(());
        }
        // Check the two MSB bits of the first byte to determine the length
        let length: u8 = match octets[0] >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unimplemented!()
        };
        let mut value: u64 = 0;
        // Remove the two MSB bits of the first byte and add the remaining bits to the value
        value |= (octets[0] & 0x3F) as u64;
        for i in 1..length {
            value <<= 8;
            value |= octets[i as usize] as u64;
        }
        Ok(Self {
            length,
            value
        })
    }
}

impl QUICInteger {
    pub fn to_binary(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let mut value = self.value;

        let index = (match self.length {
            1 => 0b00,
            2 => 0b01,
            4 => 0b10,
            8 => 0b11,
            _ => unimplemented!()
        } << 6 | (value >> (self.length - 1) * 8)) as u8;
        value &= !(0xFF << 8 * (self.length - 1));
        result.push(index);

        for _ in 1..self.length {
            result.push((value & 0xFF) as u8);
            value >>= 8;
        }
        result
    }
}



#[derive(PartialEq, Clone, Debug)]
pub struct Crypto {
    pub frame_type: QUICInteger,
    pub offset: QUICInteger,
    pub length: QUICInteger,
    pub payload: Vec<u8>
}

impl<const N: usize> TryFrom<&[u8; N]> for Crypto {
    type Error = ();

    fn try_from(octets: &[u8; N]) -> Result<Self, Self::Error> {
        if octets.len() == 0 {
            return Err(());
        }
        let frame_type = TryInto::<QUICInteger>::try_into(&octets[0..std::cmp::min(N, QUICInteger::max_length() as usize)]).unwrap();
        let offset = TryInto::<QUICInteger>::try_into(&octets[(frame_type.length as usize)..std::cmp::min(N, QUICInteger::max_length() as usize)]).unwrap();
        let length = TryInto::<QUICInteger>::try_into(&octets[(frame_type.length + offset.length) as usize..std::cmp::min(N, QUICInteger::max_length() as usize)]).unwrap();
        let payload = octets[(frame_type.length + offset.length + length.length) as usize..].to_vec();
        Ok(Self {
            frame_type,
            offset,
            length,
            payload
        })
    }
}
impl TryFrom<&[u8]> for Crypto {
    type Error = ();

    fn try_from(octets: &[u8]) -> Result<Self, Self::Error> {
        if octets.len() == 0 {
            return Err(());
        }
        let frame_type = TryInto::<QUICInteger>::try_into(&octets[0..std::cmp::min(octets.len(), QUICInteger::max_length() as usize)]).unwrap();
        let offset = TryInto::<QUICInteger>::try_into(&octets[(frame_type.length as usize)..std::cmp::min(octets.len(), QUICInteger::max_length() as usize)]).unwrap();
        let length = TryInto::<QUICInteger>::try_into(&octets[(frame_type.length + offset.length) as usize..std::cmp::min(octets.len(), QUICInteger::max_length() as usize)]).unwrap();
        let payload = octets[(frame_type.length + offset.length + length.length) as usize..].to_vec();
        Ok(Self {
            frame_type,
            offset,
            length,
            payload
        })
    }
}





#[test]
fn test_variable_integers() {
    let val_quic = TryInto::<QUICInteger>::try_into(&[0x44, 0xd9]).expect("QUIC int");
    assert_eq!(val_quic.to_binary(), vec![0x44, 0xd9]);
    let val: u16 = val_quic.try_into().unwrap();
    assert_eq!(val, 1241);

    let val2_quic = TryInto::<QUICInteger>::try_into(&[0x40, 0x7b]).expect("QUIC int");
    assert_eq!(val2_quic.to_binary(), vec![0x40, 0x7b]);
    let val2: u16 = val2_quic.try_into().unwrap();
    assert_eq!(val2, 123);

    let val3_quic = TryInto::<QUICInteger>::try_into(&[0x40, 0x3d]).expect("QUIC int");
    assert_eq!(val3_quic.to_binary(), vec![0x40, 0x3d]);
    let val3: u16 = val3_quic.try_into().unwrap();
    assert_eq!(val3, 61);

}

#[test]
fn can_decrypt_quic_crypto() {
    use hex_literal::*;
    use pnet::packet::Packet;
    /*use aes_gcm::{Aes256Gcm, Aes128Gcm, Key, Nonce}; // Or `Aes128Gcm`
    use sha2::Sha256;
    use aes_gcm::aead::{Aead, NewAead};*/

    let mut quic = hex!("c500000001088c4f1de81c072e17032f8c6f0042152b7fab163077f653ee7f52c82eb920cc69afc1c26282d27b76fcb341b8238ef14968d2d158ac58798d58a2634b93095c11492123b75be0b2f1bfa1209175a81e58b0466e3404272e4b1e1baad3e1ecaf09ef90c0ffbc206db66fb617a95a68f721594f46b720424f56fef6b6108b390f88cf2dd04043cc60bb22ef3278ec8160047c4af43c264f1403fe78f175183bf61c435b687a29d684b5906afeed56307bbc41d802721afce264d60d51abd897947459e5c930df35a4944d17e6d348d51efbc8dc2a33b1ea3122dbd774218ddcd8276b9e2ca0d9875f7717462ddee6480c1e19663653bef94d07b6de4956bbe15a85c341023311f738cdd5bda50e4e9194c435dbcec39b553812bdf8b53e607a0068f1c72d99887723e544be54663c9f79ab7e05021f2aef106ce02c6960367fbd186c4f32b2960262127658b53a719b6ad947a067f2be62cab057cbe77afbdd8ed385768aaff876d336ed7dda23dbb946d04b9a0dda311001bde540f0ffe11cf610a79b7e951f00fda76d0c2292da09cda98807e6eeb2c510e917064d1a94fd6c48f7b22ddbf374d98cadb30eb23a2822083cbe72fbd5ce72224a9790cb39cf08a10df6d3e9ca02ff7d557d6a32da271a7904b662e7b56f8f38f9f68787ab17f0b989b92dc21456f4672731344608e94557dd6d8aa01e30e01ca7c849fabc20e5018acb41b4908300042743d4ff135dde2069926a270cc4cf83b5660ca86599c9a3e8bed2ee");

    let quic = QUICPacket::new(&mut quic).unwrap();

    let initial = Initial::from_binary(quic.payload()).unwrap();
    assert_eq!(initial.length.value, 533);

    let _salt = get_quic_salt(quic.get_version());
    let _initial_secret = quic.get_dst_connection_id();

    let _encrypted = &initial.payload;

    // https://github.com/cloudflare/quiche/blob/88955b9366698b3a69b75380f081e1124d913a58/quiche/src/crypto.rs
    //
    //let hk = (Some(&salt), &initial_secret);

    /*let mut client_key = [0; 32];
    hk.expand(b"client in", &mut client_key).unwrap();

    let mut server_key = [0; 32];
    hk.expand(b"server in", &mut server_key).unwrap();

    let (client_gcm_key, client_gcm_iv )= {
        let hkdf = Hkdf::<Sha256>::new(None, &client_key);
        let mut key_buf = [0; 16];
        let mut iv_buf = [0; 12];
        hkdf.expand(b"tls13 quic key", &mut key_buf).unwrap();
        hkdf.expand(b"tls13 quic iv", &mut iv_buf).unwrap();
        (key_buf, iv_buf)
    };

    let (server_gcm_key, server_gcm_iv )= {
        let hkdf = Hkdf::<Sha256>::new(None, &server_key);
        let mut key_buf = [0; 16];
        let mut iv_buf = [0; 12];
        hkdf.expand(b"tls13 quic key", &mut key_buf).unwrap();
        hkdf.expand(b"tls13 quic iv", &mut iv_buf).unwrap();
        (key_buf, iv_buf)
    };

    // Print everything out
    println!("Client key: {:?}", client_key);
    println!("Server key: {:?}", server_key);
    println!("Client gcm key: {:?}", client_gcm_key);
    println!("Server gcm key: {:?}", server_gcm_key);
    println!("Client gcm iv: {:?}", client_gcm_iv);
    println!("Server gcm iv: {:?}", server_gcm_iv);


    let key = Key::from_slice(&server_key);
    let nonce = Nonce::from_slice(&server_gcm_iv);
    let aead = Aes128Gcm::new(key);
    let plain = aead.decrypt(nonce, quic.payload()).unwrap_err();
    println!("Plaintext: {:#?}", plain);*/

    /*
    let crypto = Crypto::try_from(initial.payload.as_slice()).unwrap();
    println!("{:?}", crypto);*/




}

