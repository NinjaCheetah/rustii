// main.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Base for the rustii CLI that handles argument parsing and directs execution to the proper module.

mod archive;
mod title;
mod filetypes;
mod info;

use anyhow::Result;
use clap::{Subcommand, Parser};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
enum Commands {
    /// Decompress data using ASH compression
    Ash {
        #[command(subcommand)]
        command: archive::ash::Commands,
    },
    /// Fakesign a TMD, Ticket, or WAD (trucha bug)
    Fakesign {
        /// The path to a TMD, Ticket, or WAD
        input: String,
        /// An (optional) output name; defaults to overwriting input file if not provided
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Get information about a TMD, Ticket, or WAD
    Info {
        /// The path to a TMD, Ticket, or WAD
        input: String,
    },
    /// Compress/decompress data using LZ77 compression
    Lz77 {
        #[command(subcommand)]
        command: archive::lz77::Commands
    },
    /// Pack/unpack/edit a WAD file
    Wad {
        #[command(subcommand)]
        command: title::wad::Commands,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match &cli.command {
        Some(Commands::Ash { command }) => {
            match command {
                archive::ash::Commands::Compress { input, output } => {
                    archive::ash::compress_ash(input, output)?
                },
                archive::ash::Commands::Decompress { input, output } => {
                    archive::ash::decompress_ash(input, output)?
                }
            }
        }
        Some(Commands::Fakesign { input, output }) => {
            title::fakesign::fakesign(input, output)?
        },
        Some(Commands::Lz77 { command }) => {
            match command {
                archive::lz77::Commands::Compress { input, output } => {
                    archive::lz77::compress_lz77(input, output)?
                },
                archive::lz77::Commands::Decompress { input, output } => {
                    archive::lz77::decompress_lz77(input, output)?
                }
            }
        },
        Some(Commands::Info { input }) => {
            info::info(input)?
        },
        Some(Commands::Wad { command }) => {
            match command {
                title::wad::Commands::Convert { input, target, output } => {
                    title::wad::convert_wad(input, target, output)?
                },
                title::wad::Commands::Pack { input, output} => {
                    title::wad::pack_wad(input, output)?
                },
                title::wad::Commands::Unpack { input, output } => {
                    title::wad::unpack_wad(input, output)?
                }
            }
        },
        None => { /* Clap handles no passed command by itself */}
    }
    Ok(())
}
