// title/wad.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for WAD-related commands in the rustii CLI.

use std::{str, fs, fmt};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::{Subcommand, Args};
use glob::glob;
use rand::prelude::*;
use rustii::title::{cert, crypto, tmd, ticket, content, wad};
use rustii::title;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Add new content to a WAD file
    Add {
        /// The path to the WAD file to modify
        input: String,
        /// The path to the new content to add
        content: String,
        /// An optional output path; defaults to overwriting input WAD file
        #[arg(short, long)]
        output: Option<String>,
        /// An optional Content ID for the new content; defaults to being randomly assigned
        #[arg(short, long)]
        cid: Option<String>,
        /// An optional type for the new content, can be "Normal", "Shared", or "DLC"; defaults to
        /// "Normal"
        #[arg(short, long)]
        r#type: Option<String>,
    },
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
    /// Remove content from a WAD file
    Remove {
        /// The path to the WAD file to modify
        input: String,
        /// An optional output path; defaults to overwriting input WAD file
        #[arg(short, long)]
        output: Option<String>,
        #[command(flatten)]
        identifier: ContentIdentifier,
    },
    /// Replace existing content in a WAD file with new data
    Set {
        /// The path to the WAD file to modify
        input: String,
        /// The path to the new content to set
        content: String,
        /// An optional output path; defaults to overwriting input WAD file
        #[arg(short, long)]
        output: Option<String>,
        /// An optional new type for the content, can be "Normal", "Shared", or "DLC"
        #[arg(short, long)]
        r#type: Option<String>,
        #[command(flatten)]
        identifier: ContentIdentifier,
    },
    /// Unpack a WAD file into a directory
    Unpack {
        /// The path to the WAD to unpack
        input: String,
        /// The directory to extract the WAD to
        output: String
    },
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

#[derive(Args)]
#[clap(next_help_heading = "Content Identifier")]
#[group(multiple = false, required = true)]
pub struct ContentIdentifier {
    /// The index of the target content
    #[arg(short, long)]
    index: Option<usize>,
    /// The Content ID of the target content
    #[arg(short, long)]
    cid: Option<String>,
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

pub fn add_wad(input: &str, content: &str, output: &Option<String>, cid: &Option<String>, ctype: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source WAD \"{}\" could not be found.", in_path.display());
    }
    let content_path = Path::new(content);
    if !content_path.exists() {
        bail!("New content \"{}\" could not be found.", content_path.display());
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap()).with_extension("wad")
    } else {
        in_path.to_path_buf()
    };
    // Load the WAD and parse the target type and Content ID.
    let mut title = title::Title::from_bytes(&fs::read(in_path)?).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
    let new_content = fs::read(content_path)?;
    let target_type = if ctype.is_some() {
        match ctype.clone().unwrap().to_ascii_lowercase().as_str() {
            "normal" => tmd::ContentType::Normal,
            "shared" => tmd::ContentType::Shared,
            "dlc" => tmd::ContentType::DLC,
            _ => bail!("The specified content type \"{}\" is invalid!", ctype.clone().unwrap()),
        }
    } else {
        tmd::ContentType::Normal
    };
    let target_cid = if cid.is_some() {
        let cid = u32::from_str_radix(cid.clone().unwrap().as_str(), 16).with_context(|| "The specified Content ID is invalid!")?;
        if title.content.content_records.iter().any(|record| record.content_id == cid) {
            bail!("The specified Content ID \"{:08X}\" is already being used in this WAD!", cid);
        }
        cid
    } else {
        // Generate a random CID if one wasn't specified, and ensure that it isn't already in use.
        let mut rng = rand::rng();
        let mut cid: u32;
        loop {
            cid = rng.random_range(0..=0xFF);
            if !title.content.content_records.iter().any(|record| record.content_id == cid) {
                break;
            }
        }
        cid
    };
    title.add_content(&new_content, target_cid, target_type.clone()).with_context(|| "An unknown error occurred while setting the new content.")?;
    title.tmd.content_records = title.content.content_records.clone();
    title.tmd.num_contents = title.content.num_contents;
    title.fakesign().with_context(|| "An unknown error occurred while fakesigning the modified WAD.")?;
    fs::write(&out_path, title.to_wad()?.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
    println!("Successfully added new content with Content ID \"{:08X}\" ({}) and type \"{}\" to WAD file \"{}\".", target_cid, target_cid, target_type, out_path.display());
    Ok(())
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
    let mut title = title::Title::from_bytes(&fs::read(in_path)?).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
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

pub fn remove_wad(input: &str, output: &Option<String>, identifier: &ContentIdentifier) ->  Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source WAD \"{}\" could not be found.", in_path.display());
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap()).with_extension("wad")
    } else {
        in_path.to_path_buf()
    };
    let mut title = title::Title::from_bytes(&fs::read(in_path)?).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
    // Parse the identifier passed to choose how to find and remove the target.
    // ...maybe don't take the above comment out of context
    if identifier.index.is_some() {
        title.content.remove_content(identifier.index.unwrap()).with_context(|| "The specified index does not exist in the provided WAD!")?;
        // Sync the content records in the TMD with the modified ones in the ContentRegion. The fact
        // that this is required is probably bad and should be addressed on the library side at some
        // point.
        title.tmd.content_records = title.content.content_records.clone();
        title.tmd.num_contents = title.content.num_contents;
        println!("{:?}", title.tmd);
        title.fakesign().with_context(|| "An unknown error occurred while fakesigning the modified WAD.")?;
        fs::write(&out_path, title.to_wad()?.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
        println!("Successfully removed content at index {} in WAD file \"{}\".", identifier.index.unwrap(), out_path.display());
    } else if identifier.cid.is_some() {
        let cid = u32::from_str_radix(identifier.cid.clone().unwrap().as_str(), 16).with_context(|| "The specified Content ID is invalid!")?;
        let index = match title.content.get_index_from_cid(cid) {
            Ok(index) => index,
            Err(_) => bail!("The specified Content ID \"{}\" ({}) does not exist in this WAD!", identifier.cid.clone().unwrap(), cid),
        };
        title.content.remove_content(index).with_context(|| "An unknown error occurred while removing content from the WAD.")?;
        // Ditto.
        title.tmd.content_records = title.content.content_records.clone();
        title.tmd.num_contents = title.content.num_contents;
        println!("{:?}", title.tmd);
        title.fakesign().with_context(|| "An unknown error occurred while fakesigning the modified WAD.")?;
        fs::write(&out_path, title.to_wad()?.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
        println!("Successfully removed content with Content ID \"{}\" ({}) in WAD file \"{}\".", identifier.cid.clone().unwrap(), cid, out_path.display());
    }
    Ok(())
}

pub fn set_wad(input: &str, content: &str, output: &Option<String>, identifier: &ContentIdentifier, ctype: &Option<String>) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source WAD \"{}\" could not be found.", in_path.display());
    }
    let content_path = Path::new(content);
    if !content_path.exists() {
        bail!("New content \"{}\" could not be found.", content_path.display());
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap()).with_extension("wad")
    } else {
        in_path.to_path_buf()
    };
    // Load the WAD and parse the new type, if one was specified.
    let mut title = title::Title::from_bytes(&fs::read(in_path)?).with_context(|| "The provided WAD file could not be parsed, and is likely invalid.")?;
    let new_content = fs::read(content_path)?;
    let mut target_type: Option<tmd::ContentType> = None;
    if ctype.is_some() {
        target_type = match ctype.clone().unwrap().to_ascii_lowercase().as_str() {
            "normal" => Some(tmd::ContentType::Normal),
            "shared" => Some(tmd::ContentType::Shared),
            "dlc" => Some(tmd::ContentType::DLC),
            _ => bail!("The specified content type \"{}\" is invalid!", ctype.clone().unwrap()),
        };
    }
    // Parse the identifier passed to choose how to do the find and replace.
    if identifier.index.is_some() {
        match title.set_content(&new_content, identifier.index.unwrap(), None, target_type) {
            Err(title::TitleError::Content(content::ContentError::IndexOutOfRange { index, max })) => {
                bail!("The specified index {} does not exist in this WAD! The maximum index is {}.", index, max)
            },
            Err(e) => bail!("An unknown error occurred while setting the new content: {e}"),
            Ok(_) => (),
        }
        title.fakesign().with_context(|| "An unknown error occurred while fakesigning the modified WAD.")?;
        fs::write(&out_path, title.to_wad()?.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
        println!("Successfully replaced content at index {} in WAD file \"{}\".", identifier.index.unwrap(), out_path.display());
    } else if identifier.cid.is_some() {
        let cid = u32::from_str_radix(identifier.cid.clone().unwrap().as_str(), 16).with_context(|| "The specified Content ID is invalid!")?;
        let index = match title.content.get_index_from_cid(cid) {
            Ok(index) => index,
            Err(_) => bail!("The specified Content ID \"{}\" ({}) does not exist in this WAD!", identifier.cid.clone().unwrap(), cid),
        };
        title.set_content(&new_content, index, None, target_type).with_context(|| "An unknown error occurred while setting the new content.")?;
        title.fakesign().with_context(|| "An unknown error occurred while fakesigning the modified WAD.")?;
        fs::write(&out_path, title.to_wad()?.to_bytes()?).with_context(|| "Could not open output file for writing.")?;
        println!("Successfully replaced content with Content ID \"{}\" ({}) in WAD file \"{}\".", identifier.cid.clone().unwrap(), cid, out_path.display());
    }
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
