// archive/lz77.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements the compression and decompression routines used for the Wii's LZ77 compression scheme.

use std::io::{Cursor, Read, Seek, SeekFrom};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LZ77Error {
    #[error("compression is type `{0}` but only 0x10 is supported")]
    InvalidCompressionType(u8),
    #[error("LZ77 data is not in a valid format")]
    IO(#[from] std::io::Error),
}

/// Decompresses LZ77-compressed data and returns the decompressed result.
pub fn decompress_lz77(data: &[u8]) -> Result<Vec<u8>, LZ77Error> {
    let mut buf = Cursor::new(data);
    // Check for magic so that we know where to start. If the compressed data was sourced from
    // inside of something, it may not have the magic and instead starts immediately at 0.
    let mut magic = [0u8; 4];
    buf.read_exact(&mut magic)?;
    if &magic != b"LZ77" {
        buf.seek(SeekFrom::Start(0))?;
    }
    // Read one byte to ensure this is compression type 0x10. Nintendo used other types, but only
    // 0x10 was supported on the Wii.
    let compression_type = buf.read_u8()?;
    if compression_type != 0x10 {
        return Err(LZ77Error::InvalidCompressionType(compression_type));
    }
    // Read the decompressed size, which is stored as 3 LE bytes for some reason.
    let decompressed_size = buf.read_u24::<LittleEndian>()? as usize;
    let mut out_buf = vec![0u8; decompressed_size];
    let mut pos = 0;
    while pos < decompressed_size {
        let flag = buf.read_u8()?;
        // Read bits in flag from most to least significant.
        let mut x = 7;
        while x >= 0 {
            // Prevents buffer overrun if the final flag is only partially used.
            if pos >= decompressed_size {
                break;
            }
            // Bit is 1, which is a reference to previous data in the file.
            if flag & (1 << x) != 0 {
                let reference = buf.read_u16::<BigEndian>()?;
                let length = 3 + ((reference >> 12) & 0xF);
                let mut offset = pos - (reference & 0xFFF) as usize - 1;
                for _ in 0..length {
                    out_buf[pos] = out_buf[offset];
                    pos += 1;
                    offset += 1;
                    // Avoids a buffer overrun if the copy length would extend past the end of the file.
                    if pos >= decompressed_size {
                        break;
                    }
                }
            } 
            // Bit is 0, which is a direct byte copy.
            else {
                out_buf[pos] = buf.read_u8()?;
                pos += 1;
            }
            x -= 1;
        }
    }
    Ok(out_buf)
}
