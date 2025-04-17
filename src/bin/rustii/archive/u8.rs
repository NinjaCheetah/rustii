// archive/u8.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Code for the U8 packing/unpacking commands in the rustii CLI.

use std::{str, fs};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
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

fn unpack_dir_recursive(dir: &Rc<RefCell<u8::U8Directory>>, out_path: PathBuf) -> Result<()> {
    let out_path = out_path.join(&dir.borrow().name);
    for file in &dir.borrow().files {
        fs::write(out_path.join(&file.borrow().name), &file.borrow().data).with_context(|| format!("Failed to write output file \"{}\".", &file.borrow().name))?;
    }
    for dir in &dir.borrow().dirs {
        if !out_path.join(&dir.borrow().name).exists() {
            fs::create_dir(out_path.join(&dir.borrow().name)).with_context(|| format!("The output directory \"{}\" could not be created.", out_path.display()))?;
        }
        unpack_dir_recursive(dir, out_path.clone())?;
    }
    Ok(())
}

pub fn unpack_u8_archive(input: &str, output: &str) -> Result<()> {
    let in_path = Path::new(input);
    if !in_path.exists() {
        bail!("Source U8 archive \"{}\" could not be found.", input);
    }
    let out_path = PathBuf::from(output);
    if out_path.exists() {
        if !out_path.is_dir() {
            bail!("A file already exists with the specified directory name!");
        }
    } else {
        fs::create_dir(&out_path).with_context(|| format!("The output directory \"{}\" could not be created.", out_path.display()))?;
    }
    // Extract the files and directories in the root, and then recurse over each directory to
    // extract the files and directories they contain.
    let u8_archive = u8::U8Archive::from_bytes(&fs::read(in_path).with_context(|| format!("Input file \"{}\" could not be read.", in_path.display()))?)?;
    unpack_dir_recursive(&u8_archive.node_tree, out_path.clone())?;
    println!("Successfully unpacked U8 archive to directory \"{}\"!", out_path.display());
    Ok(())
}
