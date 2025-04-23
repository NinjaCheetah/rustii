// title/content.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements content parsing and editing.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use sha1::{Sha1, Digest};
use thiserror::Error;
use crate::title::content::ContentError::MissingContents;
use crate::title::tmd::{ContentRecord, ContentType};
use crate::title::crypto;
use crate::title::crypto::encrypt_content;

#[derive(Debug, Error)]
pub enum ContentError {
    #[error("requested index {index} is out of range (must not exceed {max})")]
    IndexOutOfRange { index: usize, max: usize },
    #[error("expected {required} contents based on content records but found {found}")]
    MissingContents { required: usize, found: usize },
    #[error("content with requested Content ID {0} could not be found")]
    CIDNotFound(u32),
    #[error("content's hash did not match the expected value (was {hash}, expected {expected})")]
    BadHash { hash: String, expected: String },
    #[error("content data is not in a valid format")]
    IO(#[from] std::io::Error),
}

#[derive(Debug)]
/// A structure that represents the block of data containing the content of a digital Wii title.
pub struct ContentRegion {
    pub content_records: Vec<ContentRecord>,
    pub content_region_size: u32,
    pub num_contents: u16,
    pub content_start_offsets: Vec<u64>,
    pub contents: Vec<Vec<u8>>,
}

impl ContentRegion {
    /// Creates a ContentRegion instance that can be used to parse and edit content stored in a 
    /// digital Wii title from the content area of a WAD and the ContentRecords from a TMD.
    pub fn from_bytes(data: &[u8], content_records: Vec<ContentRecord>) -> Result<Self, ContentError> {
        let content_region_size = data.len() as u32;
        let num_contents = content_records.len() as u16;
        // Calculate the starting offsets of each content.
        let content_start_offsets: Vec<u64> = std::iter::once(0)
            .chain(content_records.iter().scan(0, |offset, record| {
                *offset += record.content_size;
                if record.content_size % 64 != 0 {
                    *offset += 64 - (record.content_size % 64);
                }
                Some(*offset)
            })).take(content_records.len()).collect(); // Trims the extra final entry.
        // Parse the content blob and create a vector of vectors from it.
        let mut contents: Vec<Vec<u8>> = Vec::with_capacity(num_contents as usize);
        let mut buf = Cursor::new(data);
        for i in 0..num_contents {
            buf.seek(SeekFrom::Start(content_start_offsets[i as usize]))?;
            let size = (content_records[i as usize].content_size + 15) & !15;
            let mut content = vec![0u8; size as usize];
            buf.read_exact(&mut content)?;
            contents.push(content);
        }
        Ok(ContentRegion {
            content_records,
            content_region_size,
            num_contents,
            content_start_offsets,
            contents,
        })
    }

    /// Creates a ContentRegion instance that can be used to parse and edit content stored in a 
    /// digital Wii title from a vector of contents and the ContentRecords from a TMD.
    pub fn from_contents(contents: Vec<Vec<u8>>, content_records: Vec<ContentRecord>) -> Result<Self, ContentError> {
        if contents.len() != content_records.len() {
            return Err(MissingContents { required: content_records.len(), found: contents.len()});
        }
        let mut content_region = Self::new(content_records)?;
        for i in 0..contents.len() {
            content_region.load_enc_content(&contents[i], content_region.content_records[i].index as usize)?;
        }
        Ok(content_region)
    }
    
    /// Creates a ContentRegion instance from the ContentRecords of a TMD that contains no actual
    /// content. This can be used to load existing content from files.
    pub fn new(content_records: Vec<ContentRecord>) -> Result<Self, ContentError> {
        let content_region_size: u64 = content_records.iter().map(|x| (x.content_size + 63) & !63).sum();
        let content_region_size = content_region_size as u32;
        let num_contents = content_records.len() as u16;
        let content_start_offsets: Vec<u64> = vec![0; num_contents as usize];
        let contents: Vec<Vec<u8>> = vec![Vec::new(); num_contents as usize];
        Ok(ContentRegion {
            content_records,
            content_region_size,
            num_contents,
            content_start_offsets,
            contents,
        })
    }
    
    /// Dumps the entire ContentRegion back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf: Vec<u8> = Vec::new();
        for i in 0..self.num_contents {
            let mut content = self.contents[i as usize].clone();
            // Round up size to nearest 64 to add appropriate padding.
            content.resize((content.len() + 63) & !63, 0);
            buf.write_all(&content)?;
        }
        Ok(buf)
    }

    /// Gets the encrypted content file from the ContentRegion at the specified index.
    pub fn get_enc_content_by_index(&self, index: usize) -> Result<Vec<u8>, ContentError> {
        let content = self.contents.get(index).ok_or(ContentError::IndexOutOfRange { index, max: self.content_records.len() - 1 })?;
        Ok(content.clone())
    }

    /// Gets the decrypted content file from the ContentRegion at the specified index.
    pub fn get_content_by_index(&self, index: usize, title_key: [u8; 16]) -> Result<Vec<u8>, ContentError> {
        let content = self.get_enc_content_by_index(index)?;
        // Verify the hash of the decrypted content against its record.
        let mut content_dec = crypto::decrypt_content(&content, title_key, self.content_records[index].index);
        content_dec.resize(self.content_records[index].content_size as usize, 0);
        let mut hasher = Sha1::new();
        hasher.update(content_dec.clone());
        let result = hasher.finalize();
        if result[..] != self.content_records[index].content_hash {
            return Err(ContentError::BadHash { hash: hex::encode(result), expected: hex::encode(self.content_records[index].content_hash) });
        }
        Ok(content_dec)
    }

    /// Gets the encrypted content file from the ContentRegion with the specified Content ID.
    pub fn get_enc_content_by_cid(&self, cid: u32) -> Result<Vec<u8>, ContentError> {
        let index = self.content_records.iter().position(|x| x.content_id == cid);
        if let Some(index) = index {
            let content = self.get_enc_content_by_index(index).map_err(|_| ContentError::CIDNotFound(cid))?;
            Ok(content)
        } else {
            Err(ContentError::CIDNotFound(cid))
        }
    }

    /// Gets the decrypted content file from the ContentRegion with the specified Content ID.
    pub fn get_content_by_cid(&self, cid: u32, title_key: [u8; 16]) -> Result<Vec<u8>, ContentError> {
        let index = self.content_records.iter().position(|x| x.content_id == cid);
        if let Some(index) = index {
            let content_dec = self.get_content_by_index(index, title_key)?;
            Ok(content_dec)
        } else {
            Err(ContentError::CIDNotFound(cid))
        }
    }

    /// Loads existing content into the specified index of a ContentRegion instance. This content 
    /// must be encrypted.
    pub fn load_enc_content(&mut self, content: &[u8], index: usize) -> Result<(), ContentError> {
        if index >= self.content_records.len() {
            return Err(ContentError::IndexOutOfRange { index, max: self.content_records.len() - 1 });
        }
        self.contents[index] = content.to_vec();
        Ok(())
    }
    
    /// Sets the content at the specified index to the provided encrypted content. This requires
    /// the size and hash of the original decrypted content to be known so that the appropriate
    /// values can be set in the corresponding content record. Optionally, a new Content ID or
    /// content type can be provided, with the existing values being preserved by default.
    pub fn set_enc_content(&mut self, content: &[u8], index: usize, content_size: u64, content_hash: [u8; 20], cid: Option<u32>, content_type: Option<ContentType>) -> Result<(), ContentError> {
        if index >= self.content_records.len() {
            return Err(ContentError::IndexOutOfRange { index, max: self.content_records.len() - 1 });
        }
        self.content_records[index].content_size = content_size;
        self.content_records[index].content_hash = content_hash;
        if cid.is_some() {
            self.content_records[index].content_id = cid.unwrap();
        }
        if content_type.is_some() {
            self.content_records[index].content_type = content_type.unwrap();
        }
        self.contents[index] = content.to_vec();
        Ok(())
    }
    
    /// Loads existing content into the specified index of a ContentRegion instance. This content 
    /// must be decrypted and needs to match the size and hash listed in the content record at that
    /// index.
    pub fn load_content(&mut self, content: &[u8], index: usize, title_key: [u8; 16]) -> Result<(), ContentError> {
        if index >= self.content_records.len() {
            return Err(ContentError::IndexOutOfRange { index, max: self.content_records.len() - 1 });
        }
        // Hash the content we're trying to load to ensure it matches the hash expected in the
        // matching record.
        let mut hasher = Sha1::new();
        hasher.update(content);
        let result = hasher.finalize();
        if result[..] != self.content_records[index].content_hash {
            return Err(ContentError::BadHash { hash: hex::encode(result), expected: hex::encode(self.content_records[index].content_hash) });
        }
        let content_enc = encrypt_content(content, title_key, self.content_records[index].index, self.content_records[index].content_size);
        self.contents[index] = content_enc;
        Ok(())
    }

    /// Sets the content at the specified index to the provided decrypted content. This content will
    /// have its size and hash saved into the matching record. Optionally, a new Content ID or
    /// content type can be provided, with the existing values being preserved by default. The
    /// Title Key will be used to encrypt this content before it is stored.
    pub fn set_content(&mut self, content: &[u8], index: usize, cid: Option<u32>, content_type: Option<ContentType>, title_key: [u8; 16]) -> Result<(), ContentError> {
        let content_size = content.len() as u64;
        let mut hasher = Sha1::new();
        hasher.update(content);
        let content_hash: [u8; 20] = hasher.finalize().into();
        let content_enc = encrypt_content(content, title_key, index as u16, content_size);
        self.set_enc_content(&content_enc, index, content_size, content_hash, cid, content_type)?;
        Ok(())
    }
}
