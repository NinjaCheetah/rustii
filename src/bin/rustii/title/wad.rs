// title/wad.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for WAD-related commands in the rustii CLI.

use std::{str, fs, fmt};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::{Subcommand, Args};
use glob::glob;
use rustii::title::{cert, crypto, tmd, ticket, content, wad};
use rustii::title;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Re-encrypt a WAD file with a different key
    Convert {
        /// The path to the WAD to convert
        input: String,
        /// An optional WAD name; defaults to <input name>_<new type>.wad
        #[arg(short, long)]
        output: Option<String>,
        #[command(flatten)]
        target: ConvertTargets,
    },
    /// Pack a directory into a WAD file
    Pack {
        /// The directory to pack into a WAD
        input: String,
        /// The name of the packed WAD file
        output: String
    },
    /// Unpack a WAD file into a directory
    Unpack {
        /// The path to the WAD to unpack
        input: String,
        /// The directory to extract the WAD to
        output: String
    }
}

#[derive(Args)]
#[clap(next_help_heading = "Encryption Targets")]
#[group(multiple = false, required = true)]
pub struct ConvertTargets {
    /// Use the retail common key, allowing this WAD to be installed on retail consoles and Dolphin
    #[arg(long)]
    retail: bool,
    /// Use the development common key, allowing this WAD to be installed on development consoles
    #[arg(long)]
    dev: bool,
    /// Use the vWii key, allowing this WAD to theoretically be installed from Wii U mode if a Wii U mode WAD installer is created
    #[arg(long)]
    vwii: bool,
}

enum Target {
    Retail,
    Dev,
    Vwii,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Target::Retail => write!(f, "retail"),
            Target::Dev => write!(f, "development"),
            Target::Vwii => write!(f, "vWii"),
        }
    }
}

pub fn convert_wad(input: &str, target: &ConvertTargets, output: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source WAD \"{}\" could not be found.", in_path.display());
    }
    // Parse the target passed to identify the encryption target.
    let target = if target.dev {
        Target::Dev
    } else if target.vwii {
        Target::Vwii
    } else {
        Target::Retail
    };
    // Get the output name now that we know the target, if one wasn't passed.
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap()).with_extension("wad")
    } else {
        match target {
            Target::Retail => PathBuf::from(format!("{}_retail.wad", in_path.file_stem().unwrap().to_str().unwrap())),
            Target::Dev => PathBuf::from(format!("{}_dev.wad", in_path.file_stem().unwrap().to_str().unwrap())),
            Target::Vwii => PathBuf::from(format!("{}_vWii.wad", in_path.file_stem().unwrap().to_str().unwrap())),
        }
    };
    let mut title = title::Title::from_bytes(fs::read(in_path)?.as_slice()).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
    // Bail if the WAD is already using the selected encryption.
    if matches!(target, Target::Dev) && title.ticket.is_dev() {
        bail!("This is already a development WAD!");
    } else if matches!(target, Target::Retail) && !title.ticket.is_dev() && !title.tmd.is_vwii() {
        bail!("This is already a retail WAD!");
    } else if matches!(target, Target::Vwii) && !title.ticket.is_dev() && title.tmd.is_vwii() {
        bail!("This is already a vWii WAD!");
    }
    // Save the current encryption to display at the end.
    let source = if title.ticket.is_dev() {
        "development"
    } else if title.tmd.is_vwii() {
        "vWii"
    } else {
        "retail"
    };
    let title_key = title.ticket.dec_title_key();
    let title_key_new: [u8; 16];
    match target {
        Target::Dev => {
            title.tmd.set_signature_issuer(String::from("Root-CA00000002-CP00000007"))?;
            title.ticket.set_signature_issuer(String::from("Root-CA00000002-XS00000006"))?;
            title_key_new = crypto::encrypt_title_key(title_key, 0, title.ticket.title_id, true);
            title.ticket.common_key_index = 0;
            title.tmd.is_vwii = 0;
        },
        Target::Retail => {
            title.tmd.set_signature_issuer(String::from("Root-CA00000001-CP00000004"))?;
            title.ticket.set_signature_issuer(String::from("Root-CA00000001-XS00000003"))?;
            title_key_new = crypto::encrypt_title_key(title_key, 0, title.ticket.title_id, false);
            title.ticket.common_key_index = 0;
            title.tmd.is_vwii = 0;
        },
        Target::Vwii => {
            title.tmd.set_signature_issuer(String::from("Root-CA00000001-CP00000004"))?;
            title.ticket.set_signature_issuer(String::from("Root-CA00000001-XS00000003"))?;
            title_key_new = crypto::encrypt_title_key(title_key, 2, title.ticket.title_id, false);
            title.ticket.common_key_index = 2;
            title.tmd.is_vwii = 1;
        }
    }
    title.ticket.title_key = title_key_new;
    title.fakesign()?;
    fs::write(&out_path, title.to_wad()?.to_bytes()?)?;
    println!("Successfully converted {} WAD to {} WAD \"{}\"!", source, target, out_path.file_name().unwrap().to_str().unwrap());
    Ok(())
}

pub fn pack_wad(input: &str, output: &str) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source directory \"{}\" does not exist.", in_path.display());
    }
    // Read TMD file (only accept one file).
    let tmd_files: Vec<PathBuf> = glob(&format!("{}/*.tmd", in_path.display()))?
        .filter_map(|f| f.ok()).collect();
    if tmd_files.is_empty() {
        bail!("No TMD file found in the source directory.");
    } else if tmd_files.len() > 1 {
        bail!("More than one TMD file found in the source directory.");
    }
    let mut tmd = tmd::TMD::from_bytes(&fs::read(&tmd_files[0]).with_context(|| "Could not open TMD file for reading.")?)
        .with_context(|| "The provided TMD file appears to be invalid.")?;
    // Read Ticket file (only accept one file).
    let ticket_files: Vec<PathBuf> = glob(&format!("{}/*.tik", in_path.display()))?
        .filter_map(|f| f.ok()).collect();
    if ticket_files.is_empty() {
        bail!("No Ticket file found in the source directory.");
    } else if ticket_files.len() > 1 {
        bail!("More than one Ticket file found in the source directory.");
    }
    let tik = ticket::Ticket::from_bytes(&fs::read(&ticket_files[0]).with_context(|| "Could not open Ticket file for reading.")?)
        .with_context(|| "The provided Ticket file appears to be invalid.")?;
    // Read cert chain (only accept one file).
    let cert_files: Vec<PathBuf> = glob(&format!("{}/*.cert", in_path.display()))?
        .filter_map(|f| f.ok()).collect();
    if cert_files.is_empty() {
        bail!("No cert file found in the source directory.");
    } else if cert_files.len() > 1 {
        bail!("More than one Cert file found in the source directory.");
    }
    let cert_chain = cert::CertificateChain::from_bytes(&fs::read(&cert_files[0]).with_context(|| "Could not open cert chain file for reading.")?)
        .with_context(|| "The provided certificate chain appears to be invalid.")?;
    // Read footer, if one exists (only accept one file).
    let footer_files: Vec<PathBuf> = glob(&format!("{}/*.footer", in_path.display()))?
        .filter_map(|f| f.ok()).collect();
    let mut footer: Vec<u8> = Vec::new();
    if footer_files.len() == 1 {
        footer = fs::read(&footer_files[0]).with_context(|| "Could not open footer file for reading.")?;
    }
    // Iterate over expected content and read it into a content region.
    let mut content_region = content::ContentRegion::new(tmd.content_records.clone())?;
    for content in tmd.content_records.clone() {
        let data = fs::read(format!("{}/{:08X}.app", in_path.display(), content.index)).with_context(|| format!("Could not open content file \"{:08X}.app\" for reading.", content.index))?;
        content_region.set_content(&data, content.index as usize, None, None, tik.dec_title_key())
            .with_context(|| "Failed to load content into the ContentRegion.")?;
    }
    // Ensure that the TMD is modified with our potentially updated content records.
    tmd.content_records = content_region.content_records.clone();
    let wad = wad::WAD::from_parts(&cert_chain, &[], &tik, &tmd, &content_region, &footer).with_context(|| "An unknown error occurred while building a WAD from the input files.")?;
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
    fs::write(&out_path, wad.to_bytes()?).with_context(|| format!("Could not open output file \"{}\" for writing.", out_path.display()))?;
    println!("WAD file packed!");
    Ok(())
}

pub fn unpack_wad(input: &str, output: &str) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source WAD \"{}\" could not be found.", input);
    }
    let wad_file = fs::read(in_path).with_context(|| format!("Failed to open WAD file \"{}\" for reading.", in_path.display()))?;
    let title = title::Title::from_bytes(&wad_file).with_context(|| format!("The provided WAD file \"{}\" appears to be invalid.", in_path.display()))?;
    let tid = hex::encode(title.tmd.title_id);
    // Create output directory if it doesn't exist.
    let out_path = Path::new(output);
    if !out_path.exists() {
        fs::create_dir(out_path).with_context(|| format!("The output directory \"{}\" could not be created.", out_path.display()))?;
    }
    // Write out all WAD components.
    let tmd_file_name = format!("{}.tmd", tid);
    fs::write(Path::join(out_path, tmd_file_name.clone()), title.tmd.to_bytes()?).with_context(|| format!("Failed to open TMD file \"{}\" for writing.", tmd_file_name))?;
    let ticket_file_name = format!("{}.tik", tid);
    fs::write(Path::join(out_path, ticket_file_name.clone()), title.ticket.to_bytes()?).with_context(|| format!("Failed to open Ticket file \"{}\" for writing.", ticket_file_name))?;
    let cert_file_name = format!("{}.cert", tid);
    fs::write(Path::join(out_path, cert_file_name.clone()), title.cert_chain.to_bytes()?).with_context(|| format!("Failed to open certificate chain file \"{}\" for writing.", cert_file_name))?;
    let meta_file_name = format!("{}.footer", tid);
    fs::write(Path::join(out_path, meta_file_name.clone()), title.meta()).with_context(|| format!("Failed to open footer file \"{}\" for writing.", meta_file_name))?;
    // Iterate over contents, decrypt them, and write them out.
    for i in 0..title.tmd.num_contents {
        let content_file_name = format!("{:08X}.app", title.content.content_records[i as usize].index);
        let dec_content = title.get_content_by_index(i as usize).with_context(|| format!("Failed to unpack content with Content ID {:08X}.", title.content.content_records[i as usize].content_id))?;
        fs::write(Path::join(out_path, content_file_name), dec_content).with_context(|| format!("Failed to open content file \"{:08X}.app\" for writing.", title.content.content_records[i as usize].content_id))?;
    }
    println!("WAD file unpacked!");
    Ok(())
}
