// title/wad.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for WAD-related commands in the rustii CLI.

use clap::Subcommand;
use std::{str, fs};
use std::path::Path;
use rustii::title::{tmd, ticket, wad, content};

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
    print!("packing");
}

pub fn unpack_wad(input: &str, output: &str) {
    let wad_file = fs::read(input).expect("could not read WAD");
    let wad = wad::WAD::from_bytes(&wad_file).expect("could not parse WAD");
    let tmd = tmd::TMD::from_bytes(&wad.tmd()).expect("could not parse TMD");
    let tik = ticket::Ticket::from_bytes(&wad.ticket()).expect("could not parse Ticket");
    let cert_data = &wad.cert_chain();
    let meta_data = &wad.meta();
    // Create output directory if it doesn't exist.
    if !Path::new(output).exists() {
        fs::create_dir(output).expect("could not create output directory");
    }
    let out_path = Path::new(output);
    // Write out all WAD components.
    let tmd_file_name = format!("{}.tmd", hex::encode(tmd.title_id));
    fs::write(Path::join(out_path, tmd_file_name), tmd.to_bytes().unwrap()).expect("could not write TMD file");
    let ticket_file_name = format!("{}.tik", hex::encode(tmd.title_id));
    fs::write(Path::join(out_path, ticket_file_name), tik.to_bytes().unwrap()).expect("could not write Ticket file");
    let cert_file_name = format!("{}.cert", hex::encode(tmd.title_id));
    fs::write(Path::join(out_path, cert_file_name), cert_data).expect("could not write Cert file");
    let meta_file_name = format!("{}.footer", hex::encode(tmd.title_id));
    fs::write(Path::join(out_path, meta_file_name), meta_data).expect("could not write footer file");
    // Iterate over contents, decrypt them, and write them out.
    let content_region = content::ContentRegion::from_bytes(&wad.content(), tmd.content_records).unwrap();
    for i in 0..tmd.num_contents {
        let content_file_name = format!("{:08X}.app", content_region.content_records[i as usize].index);
        let dec_content = content_region.get_content_by_index(i as usize, tik.dec_title_key()).unwrap();
        fs::write(Path::join(out_path, content_file_name), dec_content).unwrap();
    }
    println!("WAD file unpacked!");
}
