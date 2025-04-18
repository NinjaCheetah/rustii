![rustii-banner](https://github.com/user-attachments/assets/08a7eea1-837e-4bce-939e-13c720b35226)
# rustii

*Like rusty but it's rustii because the Wii? Get it?*

[![Build rustii](https://github.com/NinjaCheetah/rustii/actions/workflows/rust.yml/badge.svg)](https://github.com/NinjaCheetah/rustii/actions/workflows/rust.yml)

rustii is a library and command line tool written in Rust for handling the various files and formats found on the Wii. rustii is a port of my other library, [libWiiPy](https://github.com/NinjaCheetah/libWiiPy), which aims to accomplish the same goal in Python. Compared to libWiiPy, rustii is in its very early stages of development and is missing most of the features present in its Python counterpart. The goal is for rustii and libWiiPy to eventually have feature parity, with the rustii CLI acting as a drop-in replacement for the (comparatively much less efficient) [WiiPy](https://github.com/NinjaCheetah/WiiPy) CLI.

I'm still very new to Rust, so pardon any messy code or confusing API decisions you may find. libWiiPy started off like that, too.

### What's Included (Library-Side)
- Structs for parsing and editing WADs, TMDs, Tickets, and Certificate Chains
- Title Key and content encryption/decryption
- High-level Title struct (offering the same utility as libWiiPy's `Title`)
- LZ77 compression/decompression
- ASH decompression
- NUS TMD/Ticket/certificate chain/content downloading
- A basic CLI that uses the above features to allow for packing/unpacking WADs
- The very basics of U8 archive handling (not really functional yet though)

### What's Included (CLI-Side)
- WAD packing/unpacking/converting
- NUS TMD/Ticket/Title downloading
- LZ77 compression/decompression
- ASH decompression
- Fakesigning command for WADs/TMDs/Tickets
- Info command for WADs/TMDs/Tickets

To see specific usage information, check `rustii --help` and `rustii <command> --help`.

## Building
rustii is a standard Rust package. You'll need to have [Rust installed](https://www.rust-lang.org/learn/get-started), and then you can simply run:
```
cargo build --release
```
to compile the rustii library and CLI. The CLI can then be found at `target/release/rustii(.exe)`.
