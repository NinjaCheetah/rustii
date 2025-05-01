// nand/emunand.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for EmuNAND-related commands in the rustii CLI.

use std::{str, fs};
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use rustii::nand::emunand;
use rustii::title;

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
pub enum Commands {
    /// Placeholder command for debugging EmuNAND module
    Debug {
        /// The path to the test EmuNAND
        input: String,
    },
    InstallTitle {
        /// The path to the WAD file to install
        wad: String,
        /// The path to the target EmuNAND
        emunand: String,
    }
}

pub fn debug(input: &str) -> Result<()> {
    let emunand_root = Path::new(input);
    let emunand = emunand::EmuNAND::open(emunand_root.to_path_buf())?;
    emunand.install_title(title::Title::from_bytes(&fs::read("channel_retail.wad")?)?)?;
    Ok(())
}

pub fn install_title(wad: &str, emunand: &str) -> Result<()> {
    let wad_path = Path::new(wad);
    if !wad_path.exists() {
        bail!("Source WAD \"{}\" could not be found.", wad_path.display());
    }
    let emunand_path = Path::new(emunand);
    if !emunand_path.exists() {
        bail!("Target EmuNAND directory \"{}\" could not be found.", emunand_path.display());
    }
    let wad_file = fs::read(wad_path).with_context(|| format!("Failed to open WAD file \"{}\" for reading.", wad_path.display()))?;
    let title = title::Title::from_bytes(&wad_file).with_context(|| format!("The provided WAD file \"{}\" appears to be invalid.", wad_path.display()))?;
    let emunand = emunand::EmuNAND::open(emunand_path.to_path_buf())?;
    emunand.install_title(title)?;
    println!("Successfully installed WAD \"{}\" to EmuNAND at \"{}\"!", wad_path.display(), emunand_path.display());
    Ok(())
}
