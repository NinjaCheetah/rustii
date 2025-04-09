// archive/u8.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for the U8 packing/unpacking commands in the rustii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use rustii::archive::u8;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Pack a directory into a U8 archive
    Pack {
        /// The directory to pack into a U8 archive
        input: String,
        /// The name of the packed U8 archive
        output: String,
    },
    /// Unpack a U8 archive into a directory
    Unpack {
        /// The path to the U8 archive to unpack
        input: String,
        /// The directory to unpack the U8 archive to
        output: String,
    }
}

pub fn pack_u8_archive(_input: &str, _output: &str) -> Result<()> {
    todo!();
}

pub fn unpack_u8_archive(input: &str, output: &str) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source U8 archive \"{}\" could not be found.", input);
    }
    let u8_data = u8::U8Archive::from_bytes(&fs::read(in_path)?)?;
    println!("{:?}", u8_data);
    fs::write(Path::new(output), u8_data.to_bytes()?)?;
    Ok(())
}
