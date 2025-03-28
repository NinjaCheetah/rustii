// title/wad.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for WAD-related commands in the rustii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use clap::Subcommand;
use glob::glob;
use rustii::title::{cert, tmd, ticket, content, wad};
use rustii::title;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Pack a directory into a WAD file
    Pack {
        input: String,
        output: String
    },
    /// Unpack a WAD file into a directory
    Unpack {
        input: String,
        output: String
    }
}

pub fn pack_wad(input: &str, output: &str) {
    let in_path = Path::new(input);
    if !in_path.exists() {
        panic!("Error: Source directory does not exist.");
    }
    // Read TMD file (only accept one file).
    let tmd_files: Vec<PathBuf> = glob(&format!("{}/*.tmd", in_path.display()))
        .expect("failed to read glob pattern")
        .filter_map(|f| f.ok()).collect();
    if tmd_files.is_empty() {
        panic!("Error: No TMD file found in the source directory.");
    } else if tmd_files.len() > 1 {
        panic!("Error: More than one TMD file found in the source directory.")
    }
    let tmd = tmd::TMD::from_bytes(&fs::read(&tmd_files[0]).expect("could not read TMD file")).unwrap();
    // Read Ticket file (only accept one file).
    let ticket_files: Vec<PathBuf> = glob(&format!("{}/*.tik", in_path.display()))
        .expect("failed to read glob pattern")
        .filter_map(|f| f.ok()).collect();
    if ticket_files.is_empty() {
        panic!("Error: No Ticket file found in the source directory.");
    } else if ticket_files.len() > 1 {
        panic!("Error: More than one Ticket file found in the source directory.")
    }
    let tik = ticket::Ticket::from_bytes(&fs::read(&ticket_files[0]).expect("could not read Ticket file")).unwrap();
    // Read cert chain (only accept one file).
    let cert_files: Vec<PathBuf> = glob(&format!("{}/*.cert", in_path.display()))
        .expect("failed to read glob pattern")
        .filter_map(|f| f.ok()).collect();
    if cert_files.is_empty() {
        panic!("Error: No cert file found in the source directory.");
    } else if cert_files.len() > 1 {
        panic!("Error: More than one Cert file found in the source directory.")
    }
    let cert_chain = cert::CertificateChain::from_bytes(&fs::read(&cert_files[0]).expect("could not read cert chain file")).unwrap();
    // Read footer, if one exists (only accept one file).
    let footer_files: Vec<PathBuf> = glob(&format!("{}/*.footer", in_path.display()))
        .expect("failed to read glob pattern")
        .filter_map(|f| f.ok()).collect();
    let mut footer: Vec<u8> = Vec::new();
    if footer_files.len() == 1 {
        footer = fs::read(&footer_files[0]).unwrap();
    }
    // Iterate over expected content and read it into a content region.
    let mut content_region = content::ContentRegion::new(tmd.content_records.clone()).expect("could not create content region");
    for content in tmd.content_records.clone() {
        let data = fs::read(format!("{}/{:08X}.app", in_path.display(), content.index)).expect("could not read required content");
        content_region.load_content(&data, content.index as usize, tik.dec_title_key()).expect("failed to load content into ContentRegion");
    }
    let wad = wad::WAD::from_parts(&cert_chain, &[], &tik, &tmd, &content_region, &footer).expect("failed to create WAD");
    // Write out WAD file.
    let mut out_path = PathBuf::from(output);
    match out_path.extension() {
        Some(ext) => { 
            if ext != "wad" {
                out_path.set_extension("wad");
            }
        },
        None => {
            out_path.set_extension("wad");
        }
    }
    fs::write(out_path, wad.to_bytes().unwrap()).expect("could not write to wad file");
    println!("WAD file packed!");
}

pub fn unpack_wad(input: &str, output: &str) {
    let wad_file = fs::read(input).expect("could not read WAD");
    let title = title::Title::from_bytes(&wad_file).unwrap();
    let tid = hex::encode(title.tmd.title_id);
    // Create output directory if it doesn't exist.
    if !Path::new(output).exists() {
        fs::create_dir(output).expect("could not create output directory");
    }
    let out_path = Path::new(output);
    // Write out all WAD components.
    let tmd_file_name = format!("{}.tmd", tid);
    fs::write(Path::join(out_path, tmd_file_name), title.tmd.to_bytes().unwrap()).expect("could not write TMD file");
    let ticket_file_name = format!("{}.tik", tid);
    fs::write(Path::join(out_path, ticket_file_name), title.ticket.to_bytes().unwrap()).expect("could not write Ticket file");
    let cert_file_name = format!("{}.cert", tid);
    fs::write(Path::join(out_path, cert_file_name), title.cert_chain.to_bytes().unwrap()).expect("could not write Cert file");
    let meta_file_name = format!("{}.footer", tid);
    fs::write(Path::join(out_path, meta_file_name), title.meta()).expect("could not write footer file");
    // Iterate over contents, decrypt them, and write them out.
    for i in 0..title.tmd.num_contents {
        let content_file_name = format!("{:08X}.app", title.content.content_records[i as usize].index);
        let dec_content = title.get_content_by_index(i as usize).unwrap();
        fs::write(Path::join(out_path, content_file_name), dec_content).unwrap();
    }
    println!("WAD file unpacked!");
}
