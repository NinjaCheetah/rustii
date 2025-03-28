// title/tik.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements the structures and methods required for Ticket parsing and editing.

use std::error::Error;
use std::fmt;
use std::io::{Cursor, Read, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sha1::{Sha1, Digest};
use crate::title::crypto::decrypt_title_key;

#[derive(Debug)]
pub enum TicketError {
    UnsupportedVersion,
    CannotFakesign,
    IOError(std::io::Error),
}

impl fmt::Display for TicketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match *self {
            TicketError::UnsupportedVersion => "The provided Ticket is not a supported version (only v0 is supported).",
            TicketError::CannotFakesign => "The Ticket data could not be fakesigned.",
            TicketError::IOError(_) => "The provided Ticket data was invalid.",
        };
        f.write_str(description)
    }
}

impl Error for TicketError {}

#[derive(Debug)]
#[derive(Copy)]
#[derive(Clone)]
pub struct TitleLimit {
    // The type of limit being applied (time, launch count, etc.)
    pub limit_type: u32,
    // The maximum value for that limit (seconds, max launches, etc.)
    pub limit_max: u32,
}

#[derive(Debug)]
pub struct Ticket {
    pub signature_type: u32,
    pub signature: [u8; 256],
    padding1: [u8; 60],
    pub signature_issuer: [u8; 64],
    pub ecdh_data: [u8; 60],
    pub ticket_version: u8,
    reserved1: [u8; 2],
    pub title_key: [u8; 16],
    unknown1: [u8; 1],
    pub ticket_id: [u8; 8],
    pub console_id: [u8; 4],
    pub title_id: [u8; 8],
    unknown2: [u8; 2],
    pub title_version: u16,
    pub permitted_titles_mask: [u8; 4],
    pub permit_mask: [u8; 4],
    pub title_export_allowed: u8,
    pub common_key_index: u8,
    unknown3: [u8; 48],
    pub content_access_permission: [u8; 64],
    padding2: [u8; 2],
    pub title_limits: [TitleLimit; 8],
}

impl Ticket {
    pub fn from_bytes(data: &[u8]) -> Result<Self, TicketError> {
        let mut buf = Cursor::new(data);
        let signature_type = buf.read_u32::<BigEndian>().map_err(TicketError::IOError)?;
        let mut signature = [0u8; 256];
        buf.read_exact(&mut signature).map_err(TicketError::IOError)?;
        // Maybe this can be read differently?
        let mut padding1 = [0u8; 60];
        buf.read_exact(&mut padding1).map_err(TicketError::IOError)?;
        let mut signature_issuer = [0u8; 64];
        buf.read_exact(&mut signature_issuer).map_err(TicketError::IOError)?;
        let mut ecdh_data = [0u8; 60];
        buf.read_exact(&mut ecdh_data).map_err(TicketError::IOError)?;
        let ticket_version = buf.read_u8().map_err(TicketError::IOError)?;
        // v1 Tickets are NOT supported (just like in libWiiPy).
        if ticket_version != 0 {
            return Err(TicketError::UnsupportedVersion);
        }
        let mut reserved1 = [0u8; 2];
        buf.read_exact(&mut reserved1).map_err(TicketError::IOError)?;
        let mut title_key = [0u8; 16];
        buf.read_exact(&mut title_key).map_err(TicketError::IOError)?;
        let mut unknown1 = [0u8; 1];
        buf.read_exact(&mut unknown1).map_err(TicketError::IOError)?;
        let mut ticket_id = [0u8; 8];
        buf.read_exact(&mut ticket_id).map_err(TicketError::IOError)?;
        let mut console_id = [0u8; 4];
        buf.read_exact(&mut console_id).map_err(TicketError::IOError)?;
        let mut title_id = [0u8; 8];
        buf.read_exact(&mut title_id).map_err(TicketError::IOError)?;
        let mut unknown2 = [0u8; 2];
        buf.read_exact(&mut unknown2).map_err(TicketError::IOError)?;
        let title_version = buf.read_u16::<BigEndian>().map_err(TicketError::IOError)?;
        let mut permitted_titles_mask = [0u8; 4];
        buf.read_exact(&mut permitted_titles_mask).map_err(TicketError::IOError)?;
        let mut permit_mask = [0u8; 4];
        buf.read_exact(&mut permit_mask).map_err(TicketError::IOError)?;
        let title_export_allowed = buf.read_u8().map_err(TicketError::IOError)?;
        let common_key_index = buf.read_u8().map_err(TicketError::IOError)?;
        let mut unknown3 = [0u8; 48];
        buf.read_exact(&mut unknown3).map_err(TicketError::IOError)?;
        let mut content_access_permission = [0u8; 64];
        buf.read_exact(&mut content_access_permission).map_err(TicketError::IOError)?;
        let mut padding2 = [0u8; 2];
        buf.read_exact(&mut padding2).map_err(TicketError::IOError)?;
        // Build the array of title limits.
        let mut title_limits: Vec<TitleLimit> = Vec::new();
        for _ in 0..8 {
            let limit_type = buf.read_u32::<BigEndian>().map_err(TicketError::IOError)?;
            let limit_max = buf.read_u32::<BigEndian>().map_err(TicketError::IOError)?;
            title_limits.push(TitleLimit { limit_type, limit_max });
        }
        let title_limits = title_limits.try_into().unwrap();
        Ok(Ticket {
            signature_type,
            signature,
            padding1,
            signature_issuer,
            ecdh_data,
            ticket_version,
            reserved1,
            title_key,
            unknown1,
            ticket_id,
            console_id,
            title_id,
            unknown2,
            title_version,
            permitted_titles_mask,
            permit_mask,
            title_export_allowed,
            common_key_index,
            unknown3,
            content_access_permission,
            padding2,
            title_limits,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        buf.write_u32::<BigEndian>(self.signature_type)?;
        buf.write_all(&self.signature)?;
        buf.write_all(&self.padding1)?;
        buf.write_all(&self.signature_issuer)?;
        buf.write_all(&self.ecdh_data)?;
        buf.write_u8(self.ticket_version)?;
        buf.write_all(&self.reserved1)?;
        buf.write_all(&self.title_key)?;
        buf.write_all(&self.unknown1)?;
        buf.write_all(&self.ticket_id)?;
        buf.write_all(&self.console_id)?;
        buf.write_all(&self.title_id)?;
        buf.write_all(&self.unknown2)?;
        buf.write_u16::<BigEndian>(self.title_version)?;
        buf.write_all(&self.permitted_titles_mask)?;
        buf.write_all(&self.permit_mask)?;
        buf.write_u8(self.title_export_allowed)?;
        buf.write_u8(self.common_key_index)?;
        buf.write_all(&self.unknown3)?;
        buf.write_all(&self.content_access_permission)?;
        buf.write_all(&self.padding2)?;
        // Iterate over title limits and write out their data.
        for limit in &self.title_limits {
            buf.write_u32::<BigEndian>(limit.limit_type)?;
            buf.write_u32::<BigEndian>(limit.limit_max)?;
        }
        Ok(buf)
    }

    pub fn dec_title_key(&self) -> [u8; 16] {
        // Get the dev status of this Ticket so decrypt_title_key knows the right common key.
        let is_dev = self.is_dev();
        decrypt_title_key(self.title_key, self.common_key_index, self.title_id, Some(is_dev))
    }
    
    pub fn is_dev(&self) -> bool {
        // Parse the signature issuer to determine if this is a dev Ticket or not.
        let issuer_str = String::from_utf8(Vec::from(&self.signature_issuer)).unwrap_or_default();
        issuer_str.contains("Root-CA00000002-XS00000004") || issuer_str.contains("Root-CA00000002-XS00000006")
    }
    
    pub fn is_fakesigned(&self) -> bool {
        // Can't be fakesigned without a null signature.
        if self.signature != [0; 256] {
            return false;
        }
        // Test the hash of the Ticket body to make sure it starts with 00.
        let mut hasher = Sha1::new();
        let ticket_body = self.to_bytes().unwrap();
        hasher.update(&ticket_body[320..]);
        let result = hasher.finalize();
        if result[0] != 0 {
            return false;
        }
        true
    }
    
    pub fn fakesign(&mut self) -> Result<(), TicketError> {
        // Erase the signature.
        self.signature = [0; 256];
        let mut current_int: u16 = 0;
        let mut test_hash: [u8; 20] = [255; 20];
        while test_hash[0] != 0 {
            if current_int == 65535 { return Err(TicketError::CannotFakesign); }
            current_int += 1;
            self.unknown2 = current_int.to_be_bytes();
            let mut hasher = Sha1::new();
            let ticket_body = self.to_bytes().unwrap();
            hasher.update(&ticket_body[320..]);
            test_hash = <[u8; 20]>::from(hasher.finalize());
        }
        Ok(())
    }

    pub fn signature_issuer(&self) -> String {
        String::from_utf8_lossy(&self.signature_issuer).trim_end_matches('\0').to_owned()
    }
}
