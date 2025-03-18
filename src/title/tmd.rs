// title/tmd.rs from rustii-lib (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii-lib
//
// Implements the structures and methods required for TMD parsing and editing.

use std::io::{Cursor, Read, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

#[derive(Debug)]
pub struct ContentRecord {
    pub content_id: u32,
    pub index: u16,
    pub content_type: u16,
    pub content_size: u64,
    pub content_hash: [u8; 20],
}

#[derive(Debug)]
pub struct TMD {
    pub signature_type: u32,
    pub signature: [u8; 256],
    padding1: [u8; 60],
    pub signature_issuer: [u8; 64],
    pub tmd_version: u8,
    pub ca_crl_version: u8,
    pub signer_crl_version: u8,
    pub is_vwii: u8,
    pub ios_tid: [u8; 8],
    pub title_id: [u8; 8],
    pub title_type: [u8; 4],
    pub group_id: u16,
    padding2: [u8; 2],
    pub region: u16,
    pub ratings: [u8; 16],
    reserved1: [u8; 12],
    pub ipc_mask: [u8; 12],
    reserved2: [u8; 18],
    pub access_rights: u32,
    pub title_version: u16,
    pub num_contents: u16,
    pub boot_index: u16,
    pub minor_version: u16, // Normally unused, but good for fakesigning!
    pub content_records: Vec<ContentRecord>,
}

impl TMD {
    pub fn from_bytes(data: &[u8]) -> Result<Self, std::io::Error> {
        let mut buf = Cursor::new(data);
        let signature_type = buf.read_u32::<BigEndian>()?;
        let mut signature = [0u8; 256];
        buf.read_exact(&mut signature)?;
        // Maybe this can be read differently?
        let mut padding1 = [0u8; 60];
        buf.read_exact(&mut padding1)?;
        let mut signature_issuer = [0u8; 64];
        buf.read_exact(&mut signature_issuer)?;
        let tmd_version = buf.read_u8()?;
        let ca_crl_version = buf.read_u8()?;
        let signer_crl_version = buf.read_u8()?;
        let is_vwii = buf.read_u8()?;
        let mut ios_tid = [0u8; 8];
        buf.read_exact(&mut ios_tid)?;
        let mut title_id = [0u8; 8];
        buf.read_exact(&mut title_id)?;
        let mut title_type = [0u8; 4];
        buf.read_exact(&mut title_type)?;
        let group_id = buf.read_u16::<BigEndian>()?;
        // Same here...
        let mut padding2 = [0u8; 2];
        buf.read_exact(&mut padding2)?;
        let region = buf.read_u16::<BigEndian>()?;
        let mut ratings = [0u8; 16];
        buf.read_exact(&mut ratings)?;
        // ...and here...
        let mut reserved1 = [0u8; 12];
        buf.read_exact(&mut reserved1)?;
        let mut ipc_mask = [0u8; 12];
        buf.read_exact(&mut ipc_mask)?;
        // ...and here.
        let mut reserved2 = [0u8; 18];
        buf.read_exact(&mut reserved2)?;
        let access_rights = buf.read_u32::<BigEndian>()?;
        let title_version = buf.read_u16::<BigEndian>()?;
        let num_contents = buf.read_u16::<BigEndian>()?;
        let boot_index = buf.read_u16::<BigEndian>()?;
        let minor_version = buf.read_u16::<BigEndian>()?;
        // Build content records by iterating over the rest of the data num_contents times.
        let mut content_records = Vec::with_capacity(num_contents as usize);
        for _ in 0..num_contents {
            let content_id = buf.read_u32::<BigEndian>()?;
            let index = buf.read_u16::<BigEndian>()?;
            let content_type = buf.read_u16::<BigEndian>()?;
            let content_size = buf.read_u64::<BigEndian>()?;
            let mut content_hash = [0u8; 20];
            buf.read_exact(&mut content_hash)?;
            content_records.push(ContentRecord {
                content_id,
                index,
                content_type,
                content_size,
                content_hash,
            });
        }
        Ok(TMD {
            signature_type,
            signature,
            padding1,
            signature_issuer,
            tmd_version,
            ca_crl_version,
            signer_crl_version,
            is_vwii,
            ios_tid,
            title_id,
            title_type,
            group_id,
            padding2,
            region,
            ratings,
            reserved1,
            ipc_mask,
            reserved2,
            access_rights,
            title_version,
            num_contents,
            boot_index,
            minor_version,
            content_records,
        })
    }
    
    pub fn to_vec(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(self.signature_type)?;
        buf.write_all(&self.signature)?;
        buf.write_all(&self.padding1)?;
        buf.write_all(&self.signature_issuer)?;
        buf.write_u8(self.tmd_version)?;
        buf.write_u8(self.ca_crl_version)?;
        buf.write_u8(self.signer_crl_version)?;
        buf.write_u8(self.is_vwii)?;
        buf.write_all(&self.ios_tid)?;
        buf.write_all(&self.title_id)?;
        buf.write_all(&self.title_type)?;
        buf.write_u16::<BigEndian>(self.group_id)?;
        buf.write_all(&self.padding2)?;
        buf.write_u16::<BigEndian>(self.region)?;
        buf.write_all(&self.ratings)?;
        buf.write_all(&self.reserved1)?;
        buf.write_all(&self.ipc_mask)?;
        buf.write_all(&self.reserved2)?;
        buf.write_u32::<BigEndian>(self.access_rights)?;
        buf.write_u16::<BigEndian>(self.title_version)?;
        buf.write_u16::<BigEndian>(self.num_contents)?;
        buf.write_u16::<BigEndian>(self.boot_index)?;
        buf.write_u16::<BigEndian>(self.minor_version)?;
        // Iterate over content records and write out content record data.
        for content in &self.content_records {
            buf.write_u32::<BigEndian>(content.content_id)?;
            buf.write_u16::<BigEndian>(content.index)?;
            buf.write_u16::<BigEndian>(content.content_type)?;
            buf.write_u64::<BigEndian>(content.content_size)?;
            buf.write_all(&content.content_hash)?;
        }
        Ok(buf)
    }
    
    pub fn title_version(&self) -> u16 {
        self.title_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_load_tmd() {
        let data = fs::read("title.tmd").unwrap();
        let tmd = TMD::from_bytes(&data).unwrap();
        assert_eq!(tmd.tmd_version, 1);
    }
}

