// title/content.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements content parsing and editing.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use sha1::{Sha1, Digest};
use thiserror::Error;
use crate::title::tmd::ContentRecord;
use crate::title::crypto;

#[derive(Debug, Error)]
pub enum ContentError {
    #[error("requested index {index} is out of range (must not exceed {max})")]
    IndexOutOfRange { index: usize, max: usize },
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
        let total_content_size: u64 = content_records.iter().map(|x| (x.content_size + 63) & !63).sum();
        // Parse the content blob and create a vector of vectors from it.
        // Check that the content blob matches the total size of all the contents in the records.
        if content_region_size != total_content_size as u32 {
            println!("Content region size mismatch.");
            //return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid content blob for content records"));
        }
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
    
    /// Creates a ContentRegion instance from the ContentRecords of a TMD that contains no actual
    /// content. This can be used to load existing content from files.
    pub fn new(content_records: Vec<ContentRecord>) -> Result<Self, ContentError> {
        let content_region_size: u64 = content_records.iter().map(|x| (x.content_size + 63) & !63).sum();
        let content_region_size = content_region_size as u32;
        let num_contents = content_records.len() as u16;
        let content_start_offsets: Vec<u64> = Vec::new();
        let mut contents: Vec<Vec<u8>> = Vec::new();
        contents.resize(num_contents as usize, Vec::new());
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
        let content_enc = crypto::encrypt_content(content, title_key, self.content_records[index].index, self.content_records[index].content_size);
        self.contents[index] = content_enc;
        Ok(())
    }
}
