// title/mod.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Root for all title-related modules and implementation of the high-level Title object.

pub mod cert;
pub mod commonkeys;
pub mod content;
pub mod crypto;
pub mod ticket;
pub mod tmd;
pub mod versions;
pub mod wad;

use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum TitleError {
    BadTicket,
    BadTMD,
    BadContent,
    InvalidWAD,
    TMDError(tmd::TMDError),
    TicketError(ticket::TicketError),
    WADError(wad::WADError),
    IOError(std::io::Error),
}

impl fmt::Display for TitleError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match *self {
            TitleError::BadTicket => "The provided Ticket data was invalid.",
            TitleError::BadTMD => "The provided TMD data was invalid.",
            TitleError::BadContent => "The provided content data was invalid.",
            TitleError::InvalidWAD => "The provided WAD data was invalid.",
            TitleError::TMDError(_) => "An error occurred while processing TMD data.",
            TitleError::TicketError(_) => "An error occurred while processing ticket data.",
            TitleError::WADError(_) => "A WAD could not be built from the provided data.",
            TitleError::IOError(_) => "The provided Title data was invalid.",
        };
        f.write_str(description)
    }
}

impl Error for TitleError {}

#[derive(Debug)]
pub struct Title {
    cert_chain: Vec<u8>,
    crl: Vec<u8>,
    pub ticket: ticket::Ticket,
    pub tmd: tmd::TMD,
    pub content: content::ContentRegion,
    meta: Vec<u8>
}

impl Title {
    pub fn from_wad(wad: &wad::WAD) -> Result<Title, TitleError> {
        let ticket = ticket::Ticket::from_bytes(&wad.ticket()).map_err(|_| TitleError::BadTicket)?;
        let tmd = tmd::TMD::from_bytes(&wad.tmd()).map_err(|_| TitleError::BadTMD)?;
        let content = content::ContentRegion::from_bytes(&wad.content(), tmd.content_records.clone()).map_err(|_| TitleError::BadContent)?;
        let title = Title {
            cert_chain: wad.cert_chain(),
            crl: wad.crl(),
            ticket,
            tmd,
            content,
            meta: wad.meta(),
        };
        Ok(title)
    }
    
    pub fn to_wad(&self) -> Result<wad::WAD, TitleError> {
        // Create a new WAD from the data in the Title.
        let wad = wad::WAD::from_parts(
            &self.cert_chain,
            &self.crl,
            &self.ticket,
            &self.tmd,
            &self.content,
            &self.meta
        ).map_err(TitleError::WADError)?;
        Ok(wad)
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Result<Title, TitleError> {
        let wad = wad::WAD::from_bytes(bytes).map_err(|_| TitleError::InvalidWAD)?;
        let title = Title::from_wad(&wad)?;
        Ok(title)
    }
    
    pub fn is_fakesigned(&self) -> bool {
        self.tmd.is_fakesigned() && self.ticket.is_fakesigned()
    }
    
    pub fn fakesign(&mut self) -> Result<(), TitleError> {
        // Run the fakesign methods on the TMD and Ticket.
        self.tmd.fakesign().map_err(TitleError::TMDError)?;
        self.ticket.fakesign().map_err(TitleError::TicketError)?;
        Ok(())
    }
    
    pub fn get_content_by_index(&self, index: usize) -> Result<Vec<u8>, content::ContentError> {
        let content = self.content.get_content_by_index(index, self.ticket.dec_title_key())?;
        Ok(content)
    }
    
    pub fn get_content_by_cid(&self, cid: u32) -> Result<Vec<u8>, content::ContentError> {
        let content = self.content.get_content_by_cid(cid, self.ticket.dec_title_key())?;
        Ok(content)
    }
    
    /// Gets the installed size of the title, in bytes. Use the optional parameter "absolute" to set
    /// whether shared content should be included in this total or not.
    pub fn title_size(&self, absolute: Option<bool>) -> Result<usize, TitleError> {
        let mut title_size: usize = 0;
        // Get the TMD and Ticket size by dumping them and measuring their length for the most
        // accurate results.
        title_size += self.tmd.to_bytes().map_err(|x| TitleError::TMDError(tmd::TMDError::IOError(x)))?.len();
        title_size += self.ticket.to_bytes().map_err(|x| TitleError::TicketError(ticket::TicketError::IOError(x)))?.len();
        for record in &self.tmd.content_records {
            if matches!(record.content_type, tmd::ContentType::Shared) {
                if absolute == Some(true) {
                    title_size += record.content_size as usize;
                }
            }
            else {
                title_size += record.content_size as usize;
            }
        }
        Ok(title_size)
    }
    
    /// Gets the installed size of the title, in blocks. Use the optional parameter "absolute" to
    /// set whether shared content should be included in this total or not.
    pub fn title_size_blocks(&self, absolute: Option<bool>) -> Result<usize, TitleError> {
        let title_size_bytes = self.title_size(absolute)?;
        Ok((title_size_bytes as f64 / 131072.0).ceil() as usize)
    }
    
    pub fn cert_chain(&self) -> Vec<u8> {
        self.cert_chain.clone()
    }

    pub fn set_cert_chain(&mut self, cert_chain: &[u8]) {
        self.cert_chain = cert_chain.to_vec();
    }
    
    pub fn crl(&self) -> Vec<u8> {
        self.crl.clone()
    }
    
    pub fn set_crl(&mut self, crl: &[u8]) {
        self.crl = crl.to_vec();
    }
    
    pub fn set_ticket(&mut self, ticket: ticket::Ticket) {
        self.ticket = ticket;
    }
    
    pub fn set_tmd(&mut self, tmd: tmd::TMD) {
        self.tmd = tmd;
    }
    
    pub fn set_content(&mut self, content: content::ContentRegion) {
        self.content = content;
    }
    
    pub fn meta(&self) -> Vec<u8> {
        self.meta.clone()
    }
    
    pub fn set_meta(&mut self, meta: &[u8]) {
        self.meta = meta.to_vec();
    }
}
