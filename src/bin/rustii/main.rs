// main.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Base for the rustii CLI that handles argument parsing and directs execution to the proper module.

mod title;
use clap::{Subcommand, Parser};
use title::wad;


#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
#[command(arg_required_else_help = true)]
enum Commands {
    /// Pack/unpack/edit a WAD file
    Wad {
        #[command(subcommand)]
        command: Option<wad::Commands>,
    },
}

fn main() {
    let cli = Cli::parse();
    
    match &cli.command {
        Some(Commands::Wad { command }) => {
            match command {
                Some(wad::Commands::Pack { input, output}) => {
                    wad::pack_wad(input, output)
                },
                Some(wad::Commands::Unpack { input, output }) => {
                    wad::unpack_wad(input, output)
                },
                &None => { /* This is handled by clap */}
            }
        }
        None => {}
    }
}