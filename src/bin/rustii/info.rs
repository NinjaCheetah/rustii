// info.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for the info command in the rustii CLI.

use std::{str, fs};
use std::path::Path;
use rustii::{title, title::cert, title::tmd, title::ticket, title::wad, title::versions};
use crate::filetypes::{WiiFileType, identify_file_type};

fn tid_to_ascii(tid: [u8; 8]) -> Option<String> {
    let tid = String::from_utf8_lossy(&tid[4..]).trim_end_matches('\0').trim_start_matches('\0').to_owned();
    if tid.len() == 4 {
        Some(tid)
    } else {
        None
    }
}

fn print_tmd_info(tmd: tmd::TMD, cert: Option<cert::Certificate>) {
    // Print all important keys from the TMD.
    println!("Title Info");
    let ascii_tid = tid_to_ascii(tmd.title_id);
    if ascii_tid.is_some() {
        println!("  Title ID: {} ({})", hex::encode(tmd.title_id).to_uppercase(), ascii_tid.unwrap());
    } else {
        println!("  Title ID: {}", hex::encode(tmd.title_id).to_uppercase());
    }
    if hex::encode(tmd.title_id)[..8].eq("00000001") {
        if hex::encode(tmd.title_id).eq("0000000100000001") {
            println!("  Title Version: {} (boot2v{})", tmd.title_version, tmd.title_version);
        } else {
            println!("  Title Version: {} ({})", tmd.title_version, versions::dec_to_standard(tmd.title_version, &hex::encode(tmd.title_id), Some(tmd.is_vwii != 0)).unwrap());
        }
    } else {
        println!("  Title Version: {}", tmd.title_version);
    }
    println!("  TMD Version: {}", tmd.tmd_version);
    if hex::encode(tmd.ios_tid).eq("0000000000000000") {
        println!("  Required IOS: N/A");
    }
    else if hex::encode(tmd.ios_tid).ne(&format!("{:016X}", tmd.title_version)) {
        println!("  Required IOS: IOS{} ({})", tmd.ios_tid.last().unwrap(), hex::encode(tmd.ios_tid).to_uppercase());
    }
    let signature_issuer = String::from_utf8(Vec::from(tmd.signature_issuer)).unwrap_or_default();
    if signature_issuer.contains("CP00000004") {
        println!("  Certificate: CP00000004 (Retail)");
        println!("  Certificate Issuer: Root-CA00000001 (Retail)");
    }
    else if signature_issuer.contains("CP00000007") {
        println!("  Certificate: CP00000007 (Development)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    }
    else if signature_issuer.contains("CP00000005") {
        println!("  Certificate: CP00000005 (Development/Unknown)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    }
    else if signature_issuer.contains("CP10000000") {
        println!("  Certificate: CP10000000 (Arcade)");
        println!("  Certificate Issuer: Root-CA10000000 (Arcade)");
    }
    else {
        println!("  Certificate Info: {} (Unknown)", signature_issuer);
    }
    let region = if hex::encode(tmd.title_id).eq("0000000100000002") {
        match versions::dec_to_standard(tmd.title_version, &hex::encode(tmd.title_id), Some(tmd.is_vwii != 0))
            .unwrap_or_default().chars().last() {
            Some('U') => "USA",
            Some('E') => "EUR",
            Some('J') => "JPN",
            Some('K') => "KOR",
            _ => "None"
        }
    } else if matches!(tmd.title_type(), tmd::TitleType::System) {
        "None"
    } else {
        tmd.region()
    };
    println!("  Region: {}", region);
    println!("  Title Type: {}", tmd.title_type());
    println!("  vWii Title: {}", tmd.is_vwii != 0);
    println!("  DVD Video Access: {}", tmd.check_access_right(tmd::AccessRight::DVDVideo));
    println!("  AHB Access: {}", tmd.check_access_right(tmd::AccessRight::AHB));
    if cert.is_some() {
        let signing_str = match cert::verify_tmd(&cert.unwrap(), &tmd) {
            Ok(result) => match result {
                true => "Valid (Unmodified TMD)",
                false => {
                    if tmd.is_fakesigned() {
                        "Fakesigned"
                    } else {
                        "Invalid (Modified TMD)"
                    }
                },
            },
            Err(_) => "Invalid (Modified TMD)"
        };
        println!("  Signature: {}", signing_str);
    } else {
        println!("  Fakesigned: {}", tmd.is_fakesigned());
    }
    println!("\nContent Info");
    println!("  Total Contents: {}", tmd.num_contents);
    println!("  Boot Content Index: {}", tmd.boot_index);
    println!("  Content Records:");
    for content in tmd.content_records {
        println!("    Content Index: {}", content.index);
        println!("      Content ID: {:08X}", content.content_id);
        println!("      Content Type: {}", content.content_type);
        println!("      Content Size: {} bytes", content.content_size);
        println!("      Content Hash: {}", hex::encode(content.content_hash));
    }
}

fn print_ticket_info(ticket: ticket::Ticket, cert: Option<cert::Certificate>) {
    // Print all important keys from the Ticket.
    println!("Ticket Info");
    let ascii_tid = tid_to_ascii(ticket.title_id);
    if ascii_tid.is_some() {
        println!("  Title ID: {} ({})", hex::encode(ticket.title_id).to_uppercase(), ascii_tid.unwrap());
    } else {
        println!("  Title ID: {}", hex::encode(ticket.title_id).to_uppercase());
    }
    if hex::encode(ticket.title_id)[..8].eq("00000001") {
        if hex::encode(ticket.title_id).eq("0000000100000001") {
            println!("  Title Version: {} (boot2v{})", ticket.title_version, ticket.title_version);
        } else {
            println!("  Title Version: {} ({})", ticket.title_version, versions::dec_to_standard(ticket.title_version, &hex::encode(ticket.title_id), Some(ticket.common_key_index == 2)).unwrap());
        }
    } else {
        println!("  Title Version: {}", ticket.title_version);
    }
    println!("  Ticket Version: {}", ticket.ticket_version);
    let signature_issuer = String::from_utf8(Vec::from(ticket.signature_issuer)).unwrap_or_default();
    if signature_issuer.contains("XS00000003") {
        println!("  Certificate: XS00000003 (Retail)");
        println!("  Certificate Issuer: Root-CA00000001 (Retail)");
    } else if signature_issuer.contains("XS00000006") {
        println!("  Certificate: XS00000006 (Development)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    } else if signature_issuer.contains("XS00000004") {
        println!("  Certificate: XS00000004 (Development/Unknown)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    } else {
        println!("  Certificate Info: {} (Unknown)", signature_issuer);
    }
    let key = match ticket.common_key_index {
        0 => {
            if ticket.is_dev() { "Common (Development)" }
            else { "Common (Retail)" }
        }
        1 => "Korean",
        2 => "vWii",
        _ => "Unknown (Likely Common)"
    };
    println!("  Decryption Key: {}", key);
    println!("  Title Key (Encrypted): {}", hex::encode(ticket.title_key));
    println!("  Title Key (Decrypted): {}", hex::encode(ticket.dec_title_key()));
    if cert.is_some() {
        let signing_str = match cert::verify_ticket(&cert.unwrap(), &ticket) {
            Ok(result) => match result {
                true => "Valid (Unmodified Ticket)",
                false => {
                    if ticket.is_fakesigned() {
                        "Fakesigned"
                    } else {
                        "Invalid (Modified Ticket)"
                    }
                },
            },
            Err(_) => "Invalid (Modified Ticket)"
        };
        println!("  Signature: {}", signing_str);
    } else {
        println!("  Fakesigned: {}", ticket.is_fakesigned());
    }
}

fn print_wad_info(wad: wad::WAD) {
    println!("WAD Info");
    match wad.header.wad_type {
        wad::WADType::ImportBoot => { println!("  WAD Type: boot2") },
        wad::WADType::Installable => { println!("  WAD Type: Standard Installable") },
    }
    // Create a Title for size info, signing info and TMD/Ticket info.
    let title = title::Title::from_wad(&wad).unwrap();
    let min_size_blocks = title.title_size_blocks(None).unwrap();
    let max_size_blocks = title.title_size_blocks(Some(true)).unwrap();
    if min_size_blocks == max_size_blocks {
        println!("  Installed Size: {} blocks", min_size_blocks);
    } else {
        println!("  Installed Size: {}-{} blocks", min_size_blocks, max_size_blocks);
    }
    let min_size = title.title_size(None).unwrap() as f64 / 1048576.0;
    let max_size = title.title_size(Some(true)).unwrap() as f64 / 1048576.0;
    if min_size == max_size {
        println!("  Installed Size (MB): {:.2} MB", min_size);
    } else {
        println!("  Installed Size (MB): {:.2}-{:.2} MB", min_size, max_size);
    }
    println!("  Has Meta/Footer: {}", wad.meta_size() != 0);
    println!("  Has CRL: {}", wad.crl_size() != 0);
    let signing_str = match title.verify() {
        Ok(result) => match result {
            true => "Legitimate (Unmodified TMD + Ticket)",
            false => {
                if title.is_fakesigned() {
                    "Fakesigned"
                } else if cert::verify_tmd(&title.cert_chain.tmd_cert(), &title.tmd).unwrap() {
                    "Piratelegit (Unmodified TMD, Modified Ticket)"
                } else if  cert::verify_ticket(&title.cert_chain.ticket_cert(), &title.ticket).unwrap() {
                    "Edited (Modified TMD, Unmodified Ticket)"
                } else {
                    "Illegitimate (Modified TMD + Ticket)"
                }
            },
        },
        Err(_) => "Illegitimate (Modified TMD + Ticket)"
    };
    println!("  Signing Status: {}", signing_str);
    println!();
    print_ticket_info(title.ticket, Some(title.cert_chain.ticket_cert()));
    println!();
    print_tmd_info(title.tmd, Some(title.cert_chain.tmd_cert()));
}

pub fn info(input: &str) {
    let in_path = Path::new(input);
    if !in_path.exists() {
        panic!("Error: Input file does not exist.");
    }
    match identify_file_type(input) {
        Some(WiiFileType::Tmd) => {
            let tmd = tmd::TMD::from_bytes(fs::read(in_path).unwrap().as_slice()).unwrap();
            print_tmd_info(tmd, None);
        },
        Some(WiiFileType::Ticket) => {
            let ticket = ticket::Ticket::from_bytes(fs::read(in_path).unwrap().as_slice()).unwrap();
            print_ticket_info(ticket, None);
        },
        Some(WiiFileType::Wad) => {
            let wad = wad::WAD::from_bytes(fs::read(in_path).unwrap().as_slice()).unwrap();
            print_wad_info(wad);
        },
        None => {
            println!("Error: Information cannot be displayed for this file.");
        }
    }
}
