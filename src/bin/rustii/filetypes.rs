// filetypes.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Common code for identifying Wii file types.

use std::{str, fs::File};
use std::io::Read;
use std::path::Path;
use regex::RegexBuilder;

#[derive(Debug)]
#[derive(PartialEq)]
pub enum WiiFileType {
    Wad,
    Tmd,
    Ticket
}

pub fn identify_file_type(input: &str) -> Option<WiiFileType> {
    let input = Path::new(input);
    let re = RegexBuilder::new(r"tmd\.?[0-9]*").case_insensitive(true).build().unwrap();
    // == TMD ==
    if re.is_match(input.to_str()?) || 
        input.file_name().is_some_and(|f| f.eq_ignore_ascii_case("tmd.bin")) ||
        input.extension().is_some_and(|f| f.eq_ignore_ascii_case("tmd")) {
        return Some(WiiFileType::Tmd);
    }
    // == Ticket ==
    if input.extension().is_some_and(|f| f.eq_ignore_ascii_case("tik")) || 
        input.file_name().is_some_and(|f| f.eq_ignore_ascii_case("ticket.bin")) ||
        input.file_name().is_some_and(|f| f.eq_ignore_ascii_case("cetk")) {
        return Some(WiiFileType::Ticket);
    }
    // == WAD ==
    if input.extension().is_some_and(|f| f.eq_ignore_ascii_case("wad")) {
        return Some(WiiFileType::Wad);
    }
    // Advanced WAD detection, where we read and compare the first 8 bytes (only if the path exists.)
    if input.exists() {
        let mut f = File::open(input).unwrap();
        let mut magic_number = vec![0u8; 8];
        f.read_exact(&mut magic_number).unwrap();
        if magic_number == b"\x00\x00\x00\x20\x49\x73\x00\x00" || magic_number == b"\x00\x00\x00\x20\x69\x62\x00\x00" {
            return Some(WiiFileType::Wad);
        }
    }
    
    // == No match found! ==
    None
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_tmd() {
        assert_eq!(identify_file_type("tmd"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("TMD"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("tmd.bin"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("TMD.BIN"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("tmd.513"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("0000000100000002.tmd"), Some(WiiFileType::Tmd));
        assert_eq!(identify_file_type("0000000100000002.TMD"), Some(WiiFileType::Tmd));
    }

    #[test]
    fn test_parse_tik() {
        assert_eq!(identify_file_type("ticket.bin"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("TICKET.BIN"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("cetk"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("CETK"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("0000000100000002.tik"), Some(WiiFileType::Ticket));
        assert_eq!(identify_file_type("0000000100000002.TIK"), Some(WiiFileType::Ticket));
    }
    
    #[test]
    fn test_parse_wad() {
        assert_eq!(identify_file_type("0000000100000002.wad"), Some(WiiFileType::Wad));
        assert_eq!(identify_file_type("0000000100000002.WAD"), Some(WiiFileType::Wad));
    }
    
    #[test]
    fn test_parse_no_match() {
        assert_eq!(identify_file_type("somefile.txt"), None);
    }
}
