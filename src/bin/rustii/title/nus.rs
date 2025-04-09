// title/nus.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for NUS-related commands in the rustii CLI.

use std::{str, fs};
use std::path::PathBuf;
use anyhow::{bail, Context, Result};
use clap::{Subcommand, Args};
use rustii::title::{cert, content, nus, ticket, tmd};
use rustii::title;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Download a Ticket from the NUS
    Ticket {
        /// The Title ID that the Ticket is for
        tid: String,
        /// An optional Ticket name; defaults to <tid>.tik
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Download a title from the NUS
    Title {
        /// The Title ID of the Title to download
        tid: String,
        /// The version of the Title to download
        #[arg(short, long)]
        version: Option<String>,
        #[command(flatten)]
        output: TitleOutputType,
    },
    /// Download a TMD from the NUS
    Tmd {
        /// The Title ID that the TMD is for
        tid: String,
        /// The version of the TMD to download
        #[arg(short, long)]
        version: Option<String>,
        /// An optional TMD name; defaults to <tid>.tmd
        #[arg(short, long)]
        output: Option<String>,
    }
}

#[derive(Args)]
#[clap(next_help_heading = "Output Format")]
#[group(multiple = false, required = true)]
pub struct TitleOutputType {
    /// Download the Title data to the specified output directory
    #[arg(short, long)]
    output: Option<String>,
    /// Download the Title to a WAD file
    #[arg(short, long)]
    wad: Option<String>,
}

pub fn download_ticket(tid: &str, output: &Option<String>) -> Result<()> {
    println!("Downloading Ticket for title {tid}...");
    if tid.len() != 16 {
        bail!("The specified Title ID is invalid!");
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap())
    } else {
        PathBuf::from(format!("{}.tik", tid))
    };
    let tid: [u8; 8] = hex::decode(tid)?.try_into().unwrap();
    let tik_data = nus::download_ticket(tid, true).with_context(|| "Ticket data could not be downloaded.")?;
    fs::write(&out_path, tik_data)?;
    println!("Successfully downloaded Ticket to \"{}\"!", out_path.display());
    Ok(())
}

fn download_title_dir(title: title::Title, output: String) -> Result<()> {
    println!(" - Saving downloaded data...");
    let out_path = PathBuf::from(output);
    if out_path.exists() {
        if !out_path.is_dir() {
            bail!("A file already exists with the specified directory name!");
        }
    } else {
        fs::create_dir(&out_path).with_context(|| format!("The output directory \"{}\" could not be created.", out_path.display()))?;
    }
    let tid = hex::encode(title.tmd.title_id);
    println!("  - Saving TMD...");
    fs::write(out_path.join(format!("{}.tmd", &tid)), title.tmd.to_bytes()?).with_context(|| format!("Failed to open TMD file \"{}.tmd\" for writing.", tid))?;
    println!("  - Saving Ticket...");
    fs::write(out_path.join(format!("{}.tik", &tid)), title.ticket.to_bytes()?).with_context(|| format!("Failed to open Ticket file \"{}.tmd\" for writing.", tid))?;
    println!("  - Saving certificate chain...");
    fs::write(out_path.join(format!("{}.cert", &tid)), title.cert_chain.to_bytes()?).with_context(|| format!("Failed to open certificate chain file \"{}.cert\" for writing.", tid))?;
    // Iterate over the content files and write them out in encrypted form.
    for record in &title.content.content_records {
        println!("  - Decrypting and saving content with Content ID {}...", record.content_id);
        fs::write(out_path.join(format!("{:08X}.app", record.content_id)), title.get_content_by_cid(record.content_id)?)
            .with_context(|| format!("Failed to open content file \"{:08X}.app\" for writing.", record.content_id))?;
    }
    println!("Successfully downloaded title with Title ID {} to directory \"{}\"!", tid, out_path.display());
    Ok(())
}

fn download_title_dir_enc(tmd: tmd::TMD, content_region: content::ContentRegion, cert_chain: cert::CertificateChain, output: String) -> Result<()> {
    println!(" - Saving downloaded data...");
    let out_path = PathBuf::from(output);
    if out_path.exists() {
        if !out_path.is_dir() {
            bail!("A file already exists with the specified directory name!");
        }
    } else {
        fs::create_dir(&out_path).with_context(|| format!("The output directory \"{}\" could not be created.", out_path.display()))?;
    }
    let tid = hex::encode(tmd.title_id);
    println!("  - Saving TMD...");
    fs::write(out_path.join(format!("{}.tmd", &tid)), tmd.to_bytes()?).with_context(|| format!("Failed to open TMD file \"{}.tmd\" for writing.", tid))?;
    println!("  - Saving certificate chain...");
    fs::write(out_path.join(format!("{}.cert", &tid)), cert_chain.to_bytes()?).with_context(|| format!("Failed to open certificate chain file \"{}.cert\" for writing.", tid))?;
    // Iterate over the content files and write them out in encrypted form.
    for record in &content_region.content_records {
        println!("  - Saving content with Content ID {}...", record.content_id);
        fs::write(out_path.join(format!("{:08X}", record.content_id)), content_region.get_enc_content_by_cid(record.content_id)?)
            .with_context(|| format!("Failed to open content file \"{:08X}\" for writing.", record.content_id))?;
    }
    println!("Successfully downloaded title with Title ID {} to directory \"{}\"!", tid, out_path.display());
    Ok(())
}

fn download_title_wad(title: title::Title, output: String) -> Result<()> {
    println!(" - Packing WAD...");
    let out_path = PathBuf::from(output).with_extension("wad");
    fs::write(&out_path, title.to_wad().with_context(|| "A WAD could not be packed.")?.to_bytes()?).with_context(|| format!("Could not open WAD file \"{}\" for writing.", out_path.display()))?;
    println!("Successfully downloaded title with Title ID {} to WAD file \"{}\"!", hex::encode(title.tmd.title_id), out_path.display());
    Ok(())
}

pub fn download_title(tid: &str, version: &Option<String>, output: &TitleOutputType) -> Result<()> {
    if tid.len() != 16 {
        bail!("The specified Title ID is invalid!");
    }
    if version.is_some() {
        println!("Downloading title {} v{}, please wait...", tid, version.clone().unwrap());
    } else {
        println!("Downloading title {} vLatest, please wait...", tid);
    }
    let version: Option<u16> = if version.is_some() {
        Some(version.clone().unwrap().parse().with_context(|| "The specified Title version must be a valid integer!")?)
    } else {
        None
    };
    let tid: [u8; 8] = hex::decode(tid)?.try_into().unwrap();
    println!(" - Downloading and parsing TMD...");
    let tmd = tmd::TMD::from_bytes(&nus::download_tmd(tid, version, true).with_context(|| "TMD data could not be downloaded.")?)?;
    println!(" - Downloading and parsing Ticket...");
    let tik_res = &nus::download_ticket(tid, true);
    let tik = match tik_res {
        Ok(tik) => Some(ticket::Ticket::from_bytes(tik)?),
        Err(_) => {
            if output.wad.is_some() {
                bail!("--wad was specified, but this Title has no common Ticket and cannot be packed into a WAD!");
            } else {
                println!("  - No Ticket is available!");
                None
            }
        }
    };
    // Build a vec of contents by iterating over the content records and downloading each one.
    let mut contents: Vec<Vec<u8>> = Vec::new();
    for record in &tmd.content_records {
        println!(" - Downloading content {} of {} (Content ID: {}, Size: {} bytes)...",
            record.index + 1, &tmd.content_records.len(), record.content_id, record.content_size);
        contents.push(nus::download_content(tid, record.content_id, true).with_context(|| format!("Content with Content ID {} could not be downloaded.", record.content_id))?);
        println!("   - Done!");
    }
    let content_region = content::ContentRegion::from_contents(contents, tmd.content_records.clone())?;
    println!(" - Building certificate chain...");
    let cert_chain = cert::CertificateChain::from_bytes(&nus::download_cert_chain(true).with_context(|| "Certificate chain could not be built.")?)?;
    if tik.is_some() {
        // If we have a Ticket, then build a Title and jump to the output method.
        let title = title::Title::from_parts(cert_chain, None, tik.unwrap(), tmd, content_region, None)?;
        if output.wad.is_some() {
            download_title_wad(title, output.wad.clone().unwrap())?;
        } else {
            download_title_dir(title, output.output.clone().unwrap())?;
        }
    } else {
        // If we're downloading to a directory and have no Ticket, save the TMD and encrypted
        // contents to the directory only.
        download_title_dir_enc(tmd, content_region, cert_chain, output.output.clone().unwrap())?;
    }
    Ok(())
}

pub fn download_tmd(tid: &str, version: &Option<String>, output: &Option<String>) -> Result<()> {
    let version: Option<u16> = if version.is_some() {
        Some(version.clone().unwrap().parse().with_context(|| "The specified TMD version must be a valid integer!")?)
    } else {
        None
    };
    println!("Downloading TMD for title {tid}...");
    if tid.len() != 16 {
        bail!("The specified Title ID is invalid!");
    }
    let out_path = if output.is_some() {
        PathBuf::from(output.clone().unwrap())
    } else if version.is_some() {
        PathBuf::from(format!("{}.tmd.{}", tid, version.unwrap()))
    } else {
        PathBuf::from(format!("{}.tmd", tid))
    };
    let tid: [u8; 8] = hex::decode(tid)?.try_into().unwrap();
    let tmd_data = nus::download_tmd(tid, version, true).with_context(|| "TMD data could not be downloaded.")?;
    fs::write(&out_path, tmd_data)?;
    println!("Successfully downloaded TMD to \"{}\"!", out_path.display());
    Ok(())
}
