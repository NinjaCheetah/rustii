// archive/u8.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements the structures and methods required for parsing U8 archives.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum U8Error {
    #[error("invalid file name at offset {0}")]
    InvalidFileName(u64),
    #[error("this does not appear to be a U8 archive (missing magic number)")]
    NotU8Data,
    #[error("U8 data is not in a valid format")]
    IO(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
struct U8Node {
    node_type: u8,
    name_offset: u32, // This is really type u24, so the most significant byte will be ignored.
    data_offset: u32,
    size: u32,
}

#[derive(Debug)]
pub struct U8Archive {
    u8_nodes: Vec<U8Node>,
    file_names: Vec<String>,
    file_data: Vec<Vec<u8>>,
    root_node_offset: u32,
    header_size: u32,
    data_offset: u32,
    padding: [u8; 16],
}

impl U8Archive {
    /// Creates a new U8 instance from the binary data of a U8 file.
    pub fn from_bytes(data: &[u8]) -> Result<Self, U8Error> {
        let mut buf = Cursor::new(data);
        let mut magic = [0u8; 4];
        buf.read_exact(&mut magic)?;
        // Check for an IMET header if the magic number isn't the correct value before throwing an
        // error.
        if &magic != b"\x55\xAA\x38\x2D" {
            // Check for an IMET header immediately at the start of the file.
            buf.seek(SeekFrom::Start(0x40))?;
            buf.read_exact(&mut magic)?;
            if &magic == b"\x49\x4D\x45\x54" {
                // IMET with no build tag means the U8 archive should start at 0x600.
                buf.seek(SeekFrom::Start(0x600))?;
                buf.read_exact(&mut magic)?;
                if &magic != b"\x55\xAA\x38\x2D" {
                    return Err(U8Error::NotU8Data);
                }
                println!("ignoring IMET header at 0x40");
            }
            // Check for an IMET header that comes after a built tag.
            else {
                buf.seek(SeekFrom::Start(0x80))?;
                buf.read_exact(&mut magic)?;
                if &magic == b"\x49\x4D\x45\x54" {
                    // IMET with a build tag means the U8 archive should start at 0x600.
                    buf.seek(SeekFrom::Start(0x640))?;
                    buf.read_exact(&mut magic)?;
                    if &magic != b"\x55\xAA\x38\x2D" {
                        return Err(U8Error::NotU8Data);
                    }
                    println!("ignoring IMET header at 0x80");
                }
            }
        }
        let root_node_offset = buf.read_u32::<BigEndian>()?;
        let header_size = buf.read_u32::<BigEndian>()?;
        let data_offset = buf.read_u32::<BigEndian>()?;
        let mut padding = [0u8; 16];
        buf.read_exact(&mut padding)?;
        // Manually read the root node, since we need its size anyway to know how many nodes there
        // are total.
        let root_node_type = buf.read_u8()?;
        let root_node_name_offset = buf.read_u24::<BigEndian>()?;
        let root_node_data_offset = buf.read_u32::<BigEndian>()?;
        let root_node_size = buf.read_u32::<BigEndian>()?;
        let root_node = U8Node {
            node_type: root_node_type,
            name_offset: root_node_name_offset,
            data_offset: root_node_data_offset,
            size: root_node_size,
        };
        // Create a vec of nodes, push the root node, and then iterate over the remaining number
        // of nodes in the file and push them to the vec.
        let mut u8_nodes: Vec<U8Node> = Vec::new();
        u8_nodes.push(root_node);
        for _ in 1..root_node_size {
            let node_type = buf.read_u8()?;
            let name_offset = buf.read_u24::<BigEndian>()?;
            let data_offset = buf.read_u32::<BigEndian>()?;
            let size = buf.read_u32::<BigEndian>()?;
            u8_nodes.push(U8Node { node_type, name_offset, data_offset, size })
        }
        // Iterate over the loaded nodes and load the file names and data associated with them.
        let base_name_offset = buf.position();
        let mut file_names = Vec::<String>::new();
        let mut file_data = Vec::<Vec<u8>>::new();
        for node in &u8_nodes {
            buf.seek(SeekFrom::Start(base_name_offset + node.name_offset as u64))?;
            let mut name_bin = Vec::<u8>::new();
            // Read the file name one byte at a time until we find a null byte.
            loop {
                let byte = buf.read_u8()?;
                if byte == b'\0' {
                    break;
                }
                name_bin.push(byte);
            }
            file_names.push(String::from_utf8(name_bin).map_err(|_| U8Error::InvalidFileName(base_name_offset + node.name_offset as u64))?.to_owned());
            // If this is a file node, read the data for the file.
            if node.node_type == 0 {
                buf.seek(SeekFrom::Start(node.data_offset as u64))?;
                let mut data = vec![0u8; node.size as usize];
                buf.read_exact(&mut data)?;
                file_data.push(data);
            } else {
                file_data.push(Vec::new());
            }
        }
        Ok(U8Archive {
            u8_nodes,
            file_names,
            file_data,
            root_node_offset,
            header_size,
            data_offset,
            padding,
        })
    }

    fn pack_dir() {
        todo!();
    }

    pub fn from_dir(_input: &Path) -> Result<Self, U8Error> {
        todo!();
    }

    /// Dumps the data in a U8Archive instance back into binary data that can be written to a file.
    pub fn to_bytes(&self) -> Result<Vec<u8>, U8Error> {
        // Header size starts at 0 because the header size starts with the nodes and does not
        // include the actual file header.
        let mut header_size: u32 = 0;
        // Add 12 bytes for each node, since that's how many bytes each one is made up of.
        for _ in 0..self.u8_nodes.len() {
            header_size += 12;
        }
        // Add the number of bytes used for each file/folder name in the string table.
        for file_name in &self.file_names {
            header_size += file_name.len() as u32 + 1
        }
        // The initial data offset is equal to the file header (32 bytes) + node data aligned to
        // 64 bytes.
        let data_offset: u32 = (header_size + 32 + 63) & !63;
        // Adjust all nodes to place file data in the same order as the nodes. For some reason
        // Nintendo-made U8 archives don't necessarily do this?
        let mut current_data_offset = data_offset;
        let mut current_name_offset: u32 = 0;
        let mut u8_nodes = self.u8_nodes.clone();
        for i in 0..u8_nodes.len() {
            if u8_nodes[i].node_type == 0 {
                u8_nodes[i].data_offset = (current_data_offset + 31) & !31;
                current_data_offset += (u8_nodes[i].size + 31) & !31;
            }
            // Calculate the name offsets, including the extra 1 for the NULL byte.
            u8_nodes[i].name_offset = current_name_offset;
            current_name_offset += self.file_names[i].len() as u32 + 1
        }
        // Begin writing file data.
        let mut buf: Vec<u8> = Vec::new();
        buf.write_all(b"\x55\xAA\x38\x2D")?;
        buf.write_u32::<BigEndian>(0x20)?; // The root node offset is always 0x20.
        buf.write_u32::<BigEndian>(header_size)?;
        buf.write_u32::<BigEndian>(data_offset)?;
        buf.write_all(&self.padding)?;
        // Iterate over nodes and write them out.
        for node in &u8_nodes {
            buf.write_u8(node.node_type)?;
            buf.write_u24::<BigEndian>(node.name_offset)?;
            buf.write_u32::<BigEndian>(node.data_offset)?;
            buf.write_u32::<BigEndian>(node.size)?;
        }
        // Iterate over file names with a null byte at the end.
        for file_name in &self.file_names {
            buf.write_all(file_name.as_bytes())?;
            buf.write_u8(b'\0')?;
        }
        // Pad to the nearest multiple of 64 bytes.
        buf.resize((buf.len() + 63) & !63, 0);
        // Iterate over the file data and dump it. The file needs to be aligned to 32 bytes after
        // each write.
        for data in &self.file_data {
            buf.write_all(data)?;
            buf.resize((buf.len() + 31) & !31, 0);
        }
        Ok(buf)
    }
}
