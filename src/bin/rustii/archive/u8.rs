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
    let out_path = PathBuf::from(output);
    if out_path.exists() {
        if !out_path.is_dir() {
            bail!("A file already exists with the specified directory name!");
        }
    } else {
        fs::create_dir(&out_path).with_context(|| format!("The output directory \"{}\" could not be created.", out_path.display()))?;
    }
    let u8_archive = u8::U8Archive::from_bytes(&fs::read(in_path).with_context(|| format!("Failed to open U8 archive \"{}\" for reading.", in_path.display()))?)?;
    // This stores the path we're actively writing files to.
    let mut current_dir = out_path.clone();
    // This is the order of directory nodes we've traversed down.
    let mut parent_dirs: Vec<u32> = Vec::from([0]);
    for i in 0..u8_archive.u8_nodes.len() {
        match u8_archive.u8_nodes[i].node_type {
            1 => {
                // Code for a directory node.
                if u8_archive.u8_nodes[i].name_offset != 0 {
                    // If we're already at the correct level, make a new directory and push it to
                    // the parent_dirs vec.
                    if u8_archive.u8_nodes[i].data_offset == *parent_dirs.last().unwrap() {
                        current_dir = current_dir.join(&u8_archive.file_names[i]);
                        if !current_dir.exists() {
                            fs::create_dir(&current_dir).with_context(|| format!("Failed to create directory \"{}\".", current_dir.display()))?;
                        }
                        parent_dirs.push(i as u32);
                    }
                    // Otherwise, go back up the path until we're at the correct level.
                    else {
                        while u8_archive.u8_nodes[i].data_offset != *parent_dirs.last().unwrap() {
                            parent_dirs.pop();
                        }
                        parent_dirs.push(i as u32);
                        current_dir = out_path.clone();
                        // Rebuild current working directory, and make sure all directories in the 
                        // path exist.
                        for dir in &parent_dirs {
                            current_dir = current_dir.join(&u8_archive.file_names[*dir as usize]);
                            if !current_dir.exists() {
                                fs::create_dir(&current_dir).with_context(|| format!("Failed to create directory \"{}\".", current_dir.display()))?;
                            }
                        }
                    }
                }
            },
            0 => {
                // Code for a file node.
                fs::write(current_dir.join(&u8_archive.file_names[i]), &u8_archive.file_data[i])
                    .with_context(|| format!("Failed to write file \"{}\" in directory \"{}\".", u8_archive.file_names[i], current_dir.display()))?;
            },
            _ => bail!("Node at index {} has an invalid type! U8 archive cannot be unpacked.", i)
        }
    }
    println!("Successfully unpacked U8 archive to directory \"{}\"!", out_path.display());
    Ok(())
}
