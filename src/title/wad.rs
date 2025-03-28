// title/wad.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements the structures and methods required for WAD parsing and editing.

use std::error::Error;
use std::fmt;
use std::str;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crate::title::{cert, tmd, ticket, content};
use crate::title::ticket::TicketError;
use crate::title::tmd::TMDError;

#[derive(Debug)]
pub enum WADError {
    BadType,
    TMDError(TMDError),
    TicketError(TicketError),
    IOError(std::io::Error),
}

impl fmt::Display for WADError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let description = match *self {
            WADError::BadType => "An invalid WAD type was specified.",
            WADError::TMDError(_) => "An error occurred while loading TMD data.",
            WADError::TicketError(_) => "An error occurred while loading Ticket data.",
            WADError::IOError(_) => "The provided WAD data was invalid.",
        };
        f.write_str(description)
    }
}

impl Error for WADError {}

#[derive(Debug)]
pub enum WADType {
    Installable,
    ImportBoot
}

#[derive(Debug)]
pub struct WAD {
    pub header: WADHeader,
    pub body: WADBody,
}

#[derive(Debug)]
pub struct WADHeader {
    pub header_size: u32,
    pub wad_type: WADType,
    pub wad_version: u16,
    cert_chain_size: u32,
    crl_size: u32,
    ticket_size: u32,
    tmd_size: u32,
    content_size: u32,
    meta_size: u32,
    padding: [u8; 32],
}

#[derive(Debug)]
pub struct WADBody {
    cert_chain: Vec<u8>,
    crl: Vec<u8>,
    ticket: Vec<u8>,
    tmd: Vec<u8>,
    content: Vec<u8>,
    meta: Vec<u8>,
}

impl WADHeader {
    pub fn from_body(body: &WADBody) -> Result<WADHeader, WADError> {
        // Generates a new WADHeader from a populated WADBody object.
        // Parse the TMD and use that to determine if this is a standard WAD or a boot2 WAD.
        let tmd = tmd::TMD::from_bytes(&body.tmd).map_err(WADError::TMDError)?;
        let wad_type = match hex::encode(tmd.title_id).as_str() {
            "0000000100000001" => WADType::ImportBoot,
            _ => WADType::Installable,
        };
        // Find the sizes of all components of the Title.
        let cert_chain_size = body.cert_chain.len() as u32;
        let crl_size = body.crl.len() as u32;
        let ticket_size = body.ticket.len() as u32;
        let tmd_size = body.tmd.len() as u32;
        let content_size = body.content.len() as u32;
        let meta_size = body.meta.len() as u32;
        let header = WADHeader {
            header_size: 32,
            wad_type,
            wad_version: 0, // This is always officially a zero.
            cert_chain_size,
            crl_size,
            ticket_size,
            tmd_size,
            content_size,
            meta_size,
            padding: [0; 32],
        };
        Ok(header)
    }
}

impl WADBody {
    pub fn from_parts(cert_chain: &cert::CertificateChain, crl: &[u8], ticket: &ticket::Ticket, tmd: &tmd::TMD, 
                      content: &content::ContentRegion, meta: &[u8]) -> Result<WADBody, WADError> {
        let body = WADBody {
            cert_chain: cert_chain.to_bytes().map_err(WADError::IOError)?,
            crl: crl.to_vec(),
            ticket: ticket.to_bytes().map_err(WADError::IOError)?,
            tmd: tmd.to_bytes().map_err(WADError::IOError)?,
            content: content.to_bytes().map_err(WADError::IOError)?,
            meta: meta.to_vec(),
        };
        Ok(body)
    }
}

impl WAD {
    pub fn from_bytes(data: &[u8]) -> Result<WAD, WADError> {
        let mut buf = Cursor::new(data);
        let header_size = buf.read_u32::<BigEndian>().map_err(WADError::IOError)?;
        let mut wad_type = [0u8; 2];
        buf.read_exact(&mut wad_type).map_err(WADError::IOError)?;
        let wad_type = match str::from_utf8(&wad_type) {
            Ok(wad_type) => match wad_type {
                "Is" => WADType::Installable,
                "ib" => WADType::ImportBoot,
                _ => return Err(WADError::BadType),
            },
            Err(_) => return Err(WADError::BadType),
        };
        let wad_version = buf.read_u16::<BigEndian>().map_err(WADError::IOError)?;
        let cert_chain_size = buf.read_u32::<BigEndian>().map_err(WADError::IOError)?;
        let crl_size = buf.read_u32::<BigEndian>().map_err(WADError::IOError)?;
        let ticket_size = buf.read_u32::<BigEndian>().map_err(WADError::IOError)?;
        let tmd_size = buf.read_u32::<BigEndian>().map_err(WADError::IOError)?;
        // Round the content size to the nearest 16.
        let content_size = (buf.read_u32::<BigEndian>().map_err(WADError::IOError)? + 15) & !15;
        let meta_size = buf.read_u32::<BigEndian>().map_err(WADError::IOError)?;
        let mut padding = [0u8; 32];
        buf.read_exact(&mut padding).map_err(WADError::IOError)?;
        // Build header so we can use that data to read the WAD data.
        let header = WADHeader {
            header_size,
            wad_type,
            wad_version,
            cert_chain_size,
            crl_size,
            ticket_size,
            tmd_size,
            content_size,
            meta_size,
            padding,
        };
        // Find rounded offsets for each region.
        let cert_chain_offset = (header.header_size + 63) & !63;
        let crl_offset = (cert_chain_offset + header.cert_chain_size + 63) & !63;
        let ticket_offset = (crl_offset + header.crl_size + 63) & !63;
        let tmd_offset = (ticket_offset + header.ticket_size + 63) & !63;
        let content_offset = (tmd_offset + header.tmd_size + 63) & !63;
        let meta_offset = (content_offset + header.content_size + 63) & !63;
        // Read cert chain data.
        buf.seek(SeekFrom::Start(cert_chain_offset as u64)).map_err(WADError::IOError)?;
        let mut cert_chain = vec![0u8; header.cert_chain_size as usize];
        buf.read_exact(&mut cert_chain).map_err(WADError::IOError)?;
        buf.seek(SeekFrom::Start(crl_offset as u64)).map_err(WADError::IOError)?;
        let mut crl = vec![0u8; header.crl_size as usize];
        buf.read_exact(&mut crl).map_err(WADError::IOError)?;
        buf.seek(SeekFrom::Start(ticket_offset as u64)).map_err(WADError::IOError)?;
        let mut ticket = vec![0u8; header.ticket_size as usize];
        buf.read_exact(&mut ticket).map_err(WADError::IOError)?;
        buf.seek(SeekFrom::Start(tmd_offset as u64)).map_err(WADError::IOError)?;
        let mut tmd = vec![0u8; header.tmd_size as usize];
        buf.read_exact(&mut tmd).map_err(WADError::IOError)?;
        buf.seek(SeekFrom::Start(content_offset as u64)).map_err(WADError::IOError)?;
        let mut content = vec![0u8; header.content_size as usize];
        buf.read_exact(&mut content).map_err(WADError::IOError)?;
        buf.seek(SeekFrom::Start(meta_offset as u64)).map_err(WADError::IOError)?;
        let mut meta = vec![0u8; header.meta_size as usize];
        buf.read_exact(&mut meta).map_err(WADError::IOError)?;
        let body = WADBody {
            cert_chain,
            crl,
            ticket,
            tmd,
            content,
            meta,
        };
        // Assemble full WAD object.
        let wad = WAD {
            header,
            body,
        };
        Ok(wad)
    }
    
    pub fn from_parts(cert_chain: &cert::CertificateChain, crl: &[u8], ticket: &ticket::Ticket, tmd: &tmd::TMD,
                      content: &content::ContentRegion, meta: &[u8]) -> Result<WAD, WADError> {
        let body = WADBody::from_parts(cert_chain, crl, ticket, tmd, content, meta)?;
        let header = WADHeader::from_body(&body)?;
        let wad = WAD {
            header,
            body,
        };
        Ok(wad)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, WADError> {
        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(self.header.header_size).map_err(WADError::IOError)?;
        match self.header.wad_type {
            WADType::Installable => { buf.write("Is".as_bytes()).map_err(WADError::IOError)?; },
            WADType::ImportBoot => { buf.write("ib".as_bytes()).map_err(WADError::IOError)?; },
        }
        buf.write_u16::<BigEndian>(self.header.wad_version).map_err(WADError::IOError)?;
        buf.write_u32::<BigEndian>(self.header.cert_chain_size).map_err(WADError::IOError)?;
        buf.write_u32::<BigEndian>(self.header.crl_size).map_err(WADError::IOError)?;
        buf.write_u32::<BigEndian>(self.header.ticket_size).map_err(WADError::IOError)?;
        buf.write_u32::<BigEndian>(self.header.tmd_size).map_err(WADError::IOError)?;
        buf.write_u32::<BigEndian>(self.header.content_size).map_err(WADError::IOError)?;
        buf.write_u32::<BigEndian>(self.header.meta_size).map_err(WADError::IOError)?;
        buf.write_all(&self.header.padding).map_err(WADError::IOError)?;
        // Pad up to nearest multiple of 64. This also needs to happen after each section of data.
        buf.resize((buf.len() + 63) & !63, 0);
        buf.write_all(&self.body.cert_chain).map_err(WADError::IOError)?;
        buf.resize((buf.len() + 63) & !63, 0);
        buf.write_all(&self.body.crl).map_err(WADError::IOError)?;
        buf.resize((buf.len() + 63) & !63, 0);
        buf.write_all(&self.body.ticket).map_err(WADError::IOError)?;
        buf.resize((buf.len() + 63) & !63, 0);
        buf.write_all(&self.body.tmd).map_err(WADError::IOError)?;
        buf.resize((buf.len() + 63) & !63, 0);
        buf.write_all(&self.body.content).map_err(WADError::IOError)?;
        buf.resize((buf.len() + 63) & !63, 0);
        buf.write_all(&self.body.meta).map_err(WADError::IOError)?;
        buf.resize((buf.len() + 63) & !63, 0);
        Ok(buf)
    }
    
    pub fn cert_chain_size(&self) -> u32 { self.header.cert_chain_size }

    pub fn cert_chain(&self) -> Vec<u8> {
        self.body.cert_chain.clone()
    }
    
    pub fn set_cert_chain(&mut self, cert_chain: &[u8]) {
        self.body.cert_chain = cert_chain.to_vec();
        self.header.cert_chain_size = cert_chain.len() as u32;
    }
    
    pub fn crl_size(&self) -> u32 { self.header.crl_size }

    pub fn crl(&self) -> Vec<u8> {
        self.body.crl.clone()
    }
    
    pub fn set_crl(&mut self, crl: &[u8]) {
        self.body.crl = crl.to_vec();
        self.header.crl_size = crl.len() as u32;
    }
    
    pub fn ticket_size(&self) -> u32 { self.header.ticket_size }

    pub fn ticket(&self) -> Vec<u8> {
        self.body.ticket.clone()
    }
    
    pub fn set_ticket(&mut self, ticket: &[u8]) {
        self.body.ticket = ticket.to_vec();
        self.header.ticket_size = ticket.len() as u32;
    }
    
    pub fn tmd_size(&self) -> u32 { self.header.tmd_size }

    pub fn tmd(&self) -> Vec<u8> {
        self.body.tmd.clone()
    }
    
    pub fn set_tmd(&mut self, tmd: &[u8]) {
        self.body.tmd = tmd.to_vec();
        self.header.tmd_size = tmd.len() as u32;
    }
    
    pub fn content_size(&self) -> u32 { self.header.content_size }

    pub fn content(&self) -> Vec<u8> {
        self.body.content.clone()
    }
    
    pub fn set_content(&mut self, content: &[u8]) {
        self.body.content = content.to_vec();
        self.header.content_size = content.len() as u32;
    }
    
    pub fn meta_size(&self) -> u32 { self.header.meta_size }

    pub fn meta(&self) -> Vec<u8> {
        self.body.meta.clone()
    }
    
    pub fn set_meta(&mut self, meta: &[u8]) {
        self.body.meta = meta.to_vec();
        self.header.meta_size = meta.len() as u32;
    }
}
