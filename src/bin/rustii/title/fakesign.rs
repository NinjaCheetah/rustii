// title/fakesign.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for the fakesign command in the rustii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use rustii::{title, title::tmd, title::ticket};
use crate::filetypes::{WiiFileType, identify_file_type};

pub fn fakesign(input: &str, output: &Option<String>) {
    let in_path = Path::new(input);
    if !in_path.exists() {
        panic!("Error: Input file does not exist.");
    }
    match identify_file_type(input) {
        Some(WiiFileType::Wad) => {
            let out_path = if output.is_some() {
                PathBuf::from(output.clone().unwrap().as_str()).with_extension("wad")
            } else {
                PathBuf::from(input)
            };
            // Load WAD into a Title instance, then fakesign it.
            let mut title = title::Title::from_bytes(fs::read(in_path).unwrap().as_slice()).expect("could not read WAD file");
            title.fakesign().expect("could not fakesign WAD");
            // Write output file.
            fs::write(out_path, title.to_wad().unwrap().to_bytes().expect("could not create output WAD")).expect("could not write output WAD file");
            println!("WAD fakesigned!");
        },
        Some(WiiFileType::Tmd) => {
            let out_path = if output.is_some() {
                PathBuf::from(output.clone().unwrap().as_str()).with_extension("tmd")
            } else {
                PathBuf::from(input)
            };
            // Load TMD into a TMD instance, then fakesign it.
            let mut tmd = tmd::TMD::from_bytes(fs::read(in_path).unwrap().as_slice()).expect("could not read TMD file");
            tmd.fakesign().expect("could not fakesign TMD");
            // Write output file.
            fs::write(out_path, tmd.to_bytes().expect("could not create output TMD")).expect("could not write output TMD file");
            println!("TMD fakesigned!");
        },
        Some(WiiFileType::Ticket) => {
            let out_path = if output.is_some() {
                PathBuf::from(output.clone().unwrap().as_str()).with_extension("tik")
            } else {
                PathBuf::from(input)
            };
            // Load Ticket into a Ticket instance, then fakesign it.
            let mut ticket = ticket::Ticket::from_bytes(fs::read(in_path).unwrap().as_slice()).expect("could not read Ticket file");
            ticket.fakesign().expect("could not fakesign Ticket");
            // Write output file.
            fs::write(out_path, ticket.to_bytes().expect("could not create output Ticket")).expect("could not write output Ticket file");
            println!("Ticket fakesigned!");
        },
        None => {
            panic!("Error: You can only fakesign TMDs, Tickets, and WADs!");
        }
    }
}
