// title/tmd.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements the structures and methods required for TMD parsing and editing.

use std::cell::RefCell;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::ops::Index;
use std::rc::Rc;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sha1::{Sha1, Digest};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TMDError {
    #[error("TMD data could not be fakesigned")]
    CannotFakesign,
    #[error("signature issuer string must not exceed 64 characters (was {0})")]
    IssuerTooLong(usize),
    #[error("TMD data contains content record with invalid type `{0}`")]
    InvalidContentType(u16),
    #[error("TMD data is not in a valid format")]
    IO(#[from] std::io::Error),
}

pub enum TitleType {
    System,
    Game,
    Channel,
    SystemChannel,
    GameChannel,
    DLC,
    HiddenChannel,
    Unknown,
}

impl fmt::Display for TitleType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TitleType::System => write!(f, "System"),
            TitleType::Game => write!(f, "Game"),
            TitleType::Channel => write!(f, "Channel"),
            TitleType::SystemChannel => write!(f, "SystemChannel"),
            TitleType::GameChannel => write!(f, "GameChannel"),
            TitleType::DLC => write!(f, "DLC"),
            TitleType::HiddenChannel => write!(f, "HiddenChannel"),
            TitleType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ContentType {
    Normal = 1,
    Development = 2,
    HashTree = 3,
    DLC = 16385,
    Shared = 32769,
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ContentType::Normal => write!(f, "Normal"),
            ContentType::Development => write!(f, "Development/Unknown"),
            ContentType::HashTree => write!(f, "Hash Tree"),
            ContentType::DLC => write!(f, "DLC"),
            ContentType::Shared => write!(f, "Shared"),
        }
    }
}

pub enum AccessRight {
    AHB = 0,
    DVDVideo = 1,
}

#[derive(Debug, Clone)]
/// A structure that represents the metadata of a content file in a digital Wii title.
pub struct ContentRecord {
    pub content_id: u32,
    pub index: u16,
    pub content_type: ContentType,
    pub content_size: u64,
    pub content_hash: [u8; 20],
}

#[derive(Debug)]
/// A structure that represents a Wii TMD (Title Metadata) file.
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
    region: u16,
    pub ratings: [u8; 16],
    reserved1: [u8; 12],
    pub ipc_mask: [u8; 12],
    reserved2: [u8; 18],
    pub access_rights: u32,
    pub title_version: u16,
    pub num_contents: u16,
    pub boot_index: u16,
    pub minor_version: u16, // Normally unused, but good for fakesigning!
    pub content_records: Rc<RefCell<Vec<ContentRecord>>>,
}

impl TMD {
    /// Creates a new TMD instance from the binary data of a TMD file.
    pub fn from_bytes(data: &[u8]) -> Result<Self, TMDError> {
        let mut buf = Cursor::new(data);
        let signature_type = buf.read_u32::<BigEndian>().map_err(TMDError::IO)?;
        let mut signature = [0u8; 256];
        buf.read_exact(&mut signature).map_err(TMDError::IO)?;
        // Maybe this can be read differently?
        let mut padding1 = [0u8; 60];
        buf.read_exact(&mut padding1).map_err(TMDError::IO)?;
        let mut signature_issuer = [0u8; 64];
        buf.read_exact(&mut signature_issuer).map_err(TMDError::IO)?;
        let tmd_version = buf.read_u8().map_err(TMDError::IO)?;
        let ca_crl_version = buf.read_u8().map_err(TMDError::IO)?;
        let signer_crl_version = buf.read_u8().map_err(TMDError::IO)?;
        let is_vwii = buf.read_u8().map_err(TMDError::IO)?;
        let mut ios_tid = [0u8; 8];
        buf.read_exact(&mut ios_tid).map_err(TMDError::IO)?;
        let mut title_id = [0u8; 8];
        buf.read_exact(&mut title_id).map_err(TMDError::IO)?;
        let mut title_type = [0u8; 4];
        buf.read_exact(&mut title_type).map_err(TMDError::IO)?;
        let group_id = buf.read_u16::<BigEndian>().map_err(TMDError::IO)?;
        // Same here...
        let mut padding2 = [0u8; 2];
        buf.read_exact(&mut padding2).map_err(TMDError::IO)?;
        let region = buf.read_u16::<BigEndian>().map_err(TMDError::IO)?;
        let mut ratings = [0u8; 16];
        buf.read_exact(&mut ratings).map_err(TMDError::IO)?;
        // ...and here...
        let mut reserved1 = [0u8; 12];
        buf.read_exact(&mut reserved1).map_err(TMDError::IO)?;
        let mut ipc_mask = [0u8; 12];
        buf.read_exact(&mut ipc_mask).map_err(TMDError::IO)?;
        // ...and here.
        let mut reserved2 = [0u8; 18];
        buf.read_exact(&mut reserved2).map_err(TMDError::IO)?;
        let access_rights = buf.read_u32::<BigEndian>().map_err(TMDError::IO)?;
        let title_version = buf.read_u16::<BigEndian>().map_err(TMDError::IO)?;
        let num_contents = buf.read_u16::<BigEndian>().map_err(TMDError::IO)?;
        let boot_index = buf.read_u16::<BigEndian>().map_err(TMDError::IO)?;
        let minor_version = buf.read_u16::<BigEndian>().map_err(TMDError::IO)?;
        // Build content records by iterating over the rest of the data num_contents times.
        let mut content_records = Vec::with_capacity(num_contents as usize);
        for _ in 0..num_contents {
            let content_id = buf.read_u32::<BigEndian>().map_err(TMDError::IO)?;
            let index = buf.read_u16::<BigEndian>().map_err(TMDError::IO)?;
            let type_int = buf.read_u16::<BigEndian>().map_err(TMDError::IO)?;
            let content_type = match type_int {
                1 => ContentType::Normal,
                2 => ContentType::Development,
                3 => ContentType::HashTree,
                16385 => ContentType::DLC,
                32769 => ContentType::Shared,
                _ => return Err(TMDError::InvalidContentType(type_int))
            };
            let content_size = buf.read_u64::<BigEndian>().map_err(TMDError::IO)?;
            let mut content_hash = [0u8; 20];
            buf.read_exact(&mut content_hash).map_err(TMDError::IO)?;
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
            content_records: Rc::new(RefCell::new(content_records)),
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
        buf.write_u16::<BigEndian>(self.content_records.borrow().len() as u16)?;
        buf.write_u16::<BigEndian>(self.boot_index)?;
        buf.write_u16::<BigEndian>(self.minor_version)?;
        // Iterate over content records and write out content record data.
        for content in self.content_records.borrow().iter() {
            buf.write_u32::<BigEndian>(content.content_id)?;
            buf.write_u16::<BigEndian>(content.index)?;
            match content.content_type {
                ContentType::Normal => { buf.write_u16::<BigEndian>(1)?; },
                ContentType::Development => { buf.write_u16::<BigEndian>(2)?; },
                ContentType::HashTree => { buf.write_u16::<BigEndian>(3)?; },
                ContentType::DLC => { buf.write_u16::<BigEndian>(16385)?; },
                ContentType::Shared => { buf.write_u16::<BigEndian>(32769)?; }
            }
            buf.write_u64::<BigEndian>(content.content_size)?;
            buf.write_all(&content.content_hash)?;
        }
        Ok(buf)
    }

    /// Gets whether a TMD is fakesigned using the strncmp (trucha) bug or not.
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

    /// Fakesigns a TMD for use with the strncmp (trucha) bug.
    pub fn fakesign(&mut self) -> Result<(), TMDError> {
        // Erase the signature.
        self.signature = [0; 256];
        let mut current_int: u16 = 0;
        let mut test_hash: [u8; 20] = [255; 20];
        while test_hash[0] != 0 {
            if current_int == 65535 { return Err(TMDError::CannotFakesign); }
            current_int += 1;
            self.minor_version = current_int;
            let mut hasher = Sha1::new();
            let ticket_body = self.to_bytes()?;
            hasher.update(&ticket_body[320..]);
            test_hash = <[u8; 20]>::from(hasher.finalize());
        }
        Ok(())
    }

    /// Gets the 3-letter code of the region a TMD was created for.
    pub fn region(&self) -> &str {
        match self.region {
            0 => "JPN",
            1 => "USA",
            2 => "EUR",
            3 => "None",
            4 => "KOR",
            _ => "Unknown",
        }
    }

    /// Gets the type of title described by a TMD.
    pub fn title_type(&self) -> TitleType {
        match hex::encode(self.title_id)[..8].to_string().as_str() {
            "00000001" => TitleType::System,
            "00010000" => TitleType::Game,
            "00010001" => TitleType::Channel,
            "00010002" => TitleType::SystemChannel,
            "00010004" => TitleType::GameChannel,
            "00010005" => TitleType::DLC,
            "00010008" => TitleType::HiddenChannel,
            _ => TitleType::Unknown,
        }
    }

    /// Gets the type of content described by a content record in a TMD.
    pub fn content_type(&self, index: usize) -> ContentType {
        // Find possible content indices, because the provided one could exist while the indices
        // are out of order, which could cause problems finding the content.
        let mut content_indices = Vec::new();
        for record in self.content_records.borrow().iter() {
            content_indices.push(record.index);
        }
        let target_index = content_indices.index(index);
        match self.content_records.borrow()[*target_index as usize].content_type {
            ContentType::Normal => ContentType::Normal,
            ContentType::Development => ContentType::Development,
            ContentType::HashTree => ContentType::HashTree,
            ContentType::DLC => ContentType::DLC,
            ContentType::Shared => ContentType::Shared,
        }
    }

    /// Gets whether a specified access right is enabled in a TMD.
    pub fn check_access_right(&self, right: AccessRight) -> bool {
        self.access_rights & (1 << right as u8) != 0
    }

    /// Gets the name of the certificate used to sign a TMD as a string.
    pub fn signature_issuer(&self) -> String {
        String::from_utf8_lossy(&self.signature_issuer).trim_end_matches('\0').to_owned()
    }
    
    /// Sets a new name for the certificate used to sign a TMD.
    pub fn set_signature_issuer(&mut self, signature_issuer: String) -> Result<(), TMDError> {
        if signature_issuer.len() > 64 {
            return Err(TMDError::IssuerTooLong(signature_issuer.len()));
        }
        let mut issuer = signature_issuer.into_bytes();
        issuer.resize(64, 0);
        self.signature_issuer = issuer.try_into().unwrap();
        Ok(())
    }
    
    /// Gets whether this TMD describes a vWii title or not.
    pub fn is_vwii(&self) -> bool {
        self.is_vwii == 1
    }
}
