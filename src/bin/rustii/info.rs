// info.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for the info command in the rustii CLI.

use std::{str, fs};
use std::path::Path;
use rustii::{title, title::tmd, title::ticket, title::wad};
use crate::filetypes::{WiiFileType, identify_file_type};

fn print_tmd_info(tmd: tmd::TMD) {
    // Print all important keys from the TMD.
    println!("Title Info");
    println!("  Title ID: {}", hex::encode(tmd.title_id).to_uppercase());
    println!("  Title Version: {}", tmd.title_version);
    println!("  TMD Version: {}", tmd.tmd_version);
    if hex::encode(tmd.ios_tid) == "0000000000000000" {
        println!("  Required IOS: N/A");
    }
    else if hex::encode(tmd.ios_tid) != "0000000100000001" {
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
    println!("  Region: {}", tmd.region());
    println!("  Title Type: {}", tmd.title_type());
    println!("  vWii Title: {}", tmd.is_vwii != 0);
    println!("  DVD Video Access: {}", tmd.check_access_right(tmd::AccessRight::DVDVideo));
    println!("  AHB Access: {}", tmd.check_access_right(tmd::AccessRight::AHB));
    println!("  Fakesigned: {}", tmd.is_fakesigned());
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

fn print_ticket_info(ticket: ticket::Ticket) {
    // Print all important keys from the Ticket.
    println!("Ticket Info");
    println!("  Title ID: {}", hex::encode(ticket.title_id).to_uppercase());
    println!("  Title Version: {}", ticket.title_version);
    println!("  Ticket Version: {}", ticket.ticket_version);
    let signature_issuer = String::from_utf8(Vec::from(ticket.signature_issuer)).unwrap_or_default();
    if signature_issuer.contains("XS00000003") {
        println!("  Certificate: XS00000003 (Retail)");
        println!("  Certificate Issuer: Root-CA00000001 (Retail)");
    }
    else if signature_issuer.contains("XS00000006") {
        println!("  Certificate: XS00000006 (Development)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    }
    else if signature_issuer.contains("XS00000004") {
        println!("  Certificate: XS00000004 (Development/Unknown)");
        println!("  Certificate Issuer: Root-CA00000002 (Development)");
    }
    else {
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
    println!("  Fakesigned: {}", ticket.is_fakesigned());
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
    println!("  Installed Size: {}-{} blocks", min_size_blocks, max_size_blocks);
    let min_size = title.title_size(None).unwrap() as f64 / 1048576.0;
    let max_size = title.title_size(Some(true)).unwrap() as f64 / 1048576.0;
    println!("  Installed Size (MB): {:.2}-{:.2} MB", min_size, max_size);
    println!("  Has Meta/Footer: {}", wad.meta_size() != 0);
    println!("  Has CRL: {}", wad.crl_size() != 0);
    println!("  Fakesigned: {}", title.is_fakesigned());
    println!();
    print_ticket_info(title.ticket);
    println!();
    print_tmd_info(title.tmd);
}

pub fn info(input: &str) {
    let in_path = Path::new(input);
    if !in_path.exists() {
        panic!("Error: Input file does not exist.");
    }
    match identify_file_type(input) {
        Some(WiiFileType::Tmd) => {
            let tmd = tmd::TMD::from_bytes(fs::read(in_path).unwrap().as_slice()).unwrap();
            print_tmd_info(tmd);
        },
        Some(WiiFileType::Ticket) => {
            let ticket = ticket::Ticket::from_bytes(fs::read(in_path).unwrap().as_slice()).unwrap();
            print_ticket_info(ticket);
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
