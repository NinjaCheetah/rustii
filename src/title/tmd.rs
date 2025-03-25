// title/tmd.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements the structures and methods required for TMD parsing and editing.

use std::error::Error;
use std::fmt;
use std::io::{Cursor, Read, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sha1::{Sha1, Digest};

#[derive(Debug)]
pub enum TMDError {
    CannotFakesign,
    IOError(std::io::Error),
}

impl fmt::Display for TMDError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match *self {
            TMDError::CannotFakesign => "The TMD data could not be fakesigned.",
            TMDError::IOError(_) => "The provided TMD data was invalid.",
        };
        f.write_str(description)
    }
}

impl Error for TMDError {}

#[derive(Debug)]
#[derive(Clone)]
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
    /// Creates a new TMD instance from the binary data of a TMD file.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TMDError> {
        let mut buf = Cursor::new(data);
        let signature_type = buf.read_u32::<BigEndian>().map_err(TMDError::IOError)?;
        let mut signature = [0u8; 256];
        buf.read_exact(&mut signature).map_err(TMDError::IOError)?;
        // Maybe this can be read differently?
        let mut padding1 = [0u8; 60];
        buf.read_exact(&mut padding1).map_err(TMDError::IOError)?;
        let mut signature_issuer = [0u8; 64];
        buf.read_exact(&mut signature_issuer).map_err(TMDError::IOError)?;
        let tmd_version = buf.read_u8().map_err(TMDError::IOError)?;
        let ca_crl_version = buf.read_u8().map_err(TMDError::IOError)?;
        let signer_crl_version = buf.read_u8().map_err(TMDError::IOError)?;
        let is_vwii = buf.read_u8().map_err(TMDError::IOError)?;
        let mut ios_tid = [0u8; 8];
        buf.read_exact(&mut ios_tid).map_err(TMDError::IOError)?;
        let mut title_id = [0u8; 8];
        buf.read_exact(&mut title_id).map_err(TMDError::IOError)?;
        let mut title_type = [0u8; 4];
        buf.read_exact(&mut title_type).map_err(TMDError::IOError)?;
        let group_id = buf.read_u16::<BigEndian>().map_err(TMDError::IOError)?;
        // Same here...
        let mut padding2 = [0u8; 2];
        buf.read_exact(&mut padding2).map_err(TMDError::IOError)?;
        let region = buf.read_u16::<BigEndian>().map_err(TMDError::IOError)?;
        let mut ratings = [0u8; 16];
        buf.read_exact(&mut ratings).map_err(TMDError::IOError)?;
        // ...and here...
        let mut reserved1 = [0u8; 12];
        buf.read_exact(&mut reserved1).map_err(TMDError::IOError)?;
        let mut ipc_mask = [0u8; 12];
        buf.read_exact(&mut ipc_mask).map_err(TMDError::IOError)?;
        // ...and here.
        let mut reserved2 = [0u8; 18];
        buf.read_exact(&mut reserved2).map_err(TMDError::IOError)?;
        let access_rights = buf.read_u32::<BigEndian>().map_err(TMDError::IOError)?;
        let title_version = buf.read_u16::<BigEndian>().map_err(TMDError::IOError)?;
        let num_contents = buf.read_u16::<BigEndian>().map_err(TMDError::IOError)?;
        let boot_index = buf.read_u16::<BigEndian>().map_err(TMDError::IOError)?;
        let minor_version = buf.read_u16::<BigEndian>().map_err(TMDError::IOError)?;
        // Build content records by iterating over the rest of the data num_contents times.
        let mut content_records = Vec::with_capacity(num_contents as usize);
        for _ in 0..num_contents {
            let content_id = buf.read_u32::<BigEndian>().map_err(TMDError::IOError)?;
            let index = buf.read_u16::<BigEndian>().map_err(TMDError::IOError)?;
            let content_type = buf.read_u16::<BigEndian>().map_err(TMDError::IOError)?;
            let content_size = buf.read_u64::<BigEndian>().map_err(TMDError::IOError)?;
            let mut content_hash = [0u8; 20];
            buf.read_exact(&mut content_hash).map_err(TMDError::IOError)?;
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
    
    /// Dumps the data in a TMD back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
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

    pub fn is_fakesigned(&self) -> bool {
        // Can't be fakesigned without a null signature.
        if self.signature != [0; 256] {
            return false;
        }
        // Test the hash of the TMD body to make sure it starts with 00.
        let mut hasher = Sha1::new();
        let tmd_body = self.to_bytes().unwrap();
        hasher.update(&tmd_body[320..]);
        let result = hasher.finalize();
        if result[0] != 0 {
            return false;
        }
        true
    }

    pub fn fakesign(&mut self) -> Result<(), TMDError> {
        // Erase the signature.
        self.signature = [0; 256];
        let mut current_int: u16 = 0;
        let mut test_hash: [u8; 20] = [255; 20];
        while test_hash[0] != 0 {
            if current_int == 255 { return Err(TMDError::CannotFakesign); }
            current_int += 1;
            self.minor_version = current_int;
            let mut hasher = Sha1::new();
            let ticket_body = self.to_bytes().unwrap();
            hasher.update(&ticket_body[320..]);
            test_hash = <[u8; 20]>::from(hasher.finalize());
        }
        Ok(())
    }
}
