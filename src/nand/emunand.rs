// nand/emunand.rs from rustii (c) 2025 NinjaCheetah & Contributors
// https://github.com/NinjaCheetah/rustii
//
// Implements the structures and methods required for handling Wii EmuNANDs.

use std::fs;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use crate::nand::sys;
use crate::title;
use crate::title::{cert, content, ticket, tmd};

#[derive(Debug, Error)]
pub enum EmuNANDError {
    #[error("EmuNAND requires the directory `{0}`, but a file with that name already exists")]
    DirectoryNameConflict(String),
    #[error("specified EmuNAND root does not exist")]
    RootNotFound,
    #[error("uid.sys processing error")]
    UidSys(#[from] sys::UidSysError),
    #[error("certificate processing error")]
    CertificateError(#[from] cert::CertificateError),
    #[error("TMD processing error")]
    TMD(#[from] tmd::TMDError),
    #[error("Ticket processing error")]
    Ticket(#[from] ticket::TicketError),
    #[error("content processing error")]
    Content(#[from] content::ContentError),
    #[error("io error occurred during EmuNAND operation")]
    IO(#[from] std::io::Error),
}

fn safe_create_dir(dir: &PathBuf) -> Result<(), EmuNANDError> {
    if !dir.exists() {
        fs::create_dir(dir)?;
    } else if !dir.is_dir() {
        return Err(EmuNANDError::DirectoryNameConflict(dir.to_str().unwrap().to_string()));
    }
    Ok(())
}

/// An EmuNAND object that allows for creating and modifying Wii EmuNANDs.
pub struct EmuNAND {
    emunand_root: PathBuf,
    emunand_dirs: HashMap<String, PathBuf>,
}

impl EmuNAND {
    /// Open an existing EmuNAND in an EmuNAND instance that can be used to interact with it. This
    /// will initialize the basic directory structure if it doesn't already exist, but will not do
    /// anything beyond that.
    pub fn open(emunand_root: PathBuf) -> Result<Self, EmuNANDError> {
        if !emunand_root.exists() {
            return Err(EmuNANDError::RootNotFound);
        }
        let mut emunand_dirs: HashMap<String, PathBuf> = HashMap::new();
        emunand_dirs.insert(String::from("import"), emunand_root.join("import"));
        emunand_dirs.insert(String::from("meta"), emunand_root.join("meta"));
        emunand_dirs.insert(String::from("shared1"), emunand_root.join("shared1"));
        emunand_dirs.insert(String::from("shared2"), emunand_root.join("shared2"));
        emunand_dirs.insert(String::from("sys"), emunand_root.join("sys"));
        emunand_dirs.insert(String::from("ticket"), emunand_root.join("ticket"));
        emunand_dirs.insert(String::from("title"), emunand_root.join("title"));
        emunand_dirs.insert(String::from("tmp"), emunand_root.join("tmp"));
        emunand_dirs.insert(String::from("wfs"), emunand_root.join("wfs"));
        for dir in emunand_dirs.keys() {
            if !emunand_dirs[dir].exists() {
                fs::create_dir(&emunand_dirs[dir])?;
            } else if !emunand_dirs[dir].is_dir() {
                return Err(EmuNANDError::DirectoryNameConflict(emunand_dirs[dir].to_str().unwrap().to_string()));
            }
        }
        Ok(EmuNAND {
            emunand_root,
            emunand_dirs,
        })
    }
    
    /// Install the provided title to the EmuNAND, mimicking a WAD installation performed by ES.
    pub fn install_title(&self, title: title::Title) -> Result<(), EmuNANDError> {
        // Save the two halves of the TID, since those are part of the installation path.
        let tid_high = hex::encode(&title.tmd.title_id()[0..4]);
        let tid_low = hex::encode(&title.tmd.title_id()[4..8]);
        // Tickets are installed to /ticket/<tid_high>/<tid_low>.tik.
        let ticket_dir = self.emunand_dirs["ticket"].join(&tid_high);
        safe_create_dir(&ticket_dir)?;
        fs::write(ticket_dir.join(format!("{}.tik", &tid_low)), title.ticket.to_bytes()?)?;
        // TMDs and normal content (non-shared) are installed to 
        // /title/<tid_high>/<tid_low>/content/, as title.tmd and <cid>.app.
        let mut title_dir = self.emunand_dirs["title"].join(&tid_high);
        safe_create_dir(&title_dir)?;
        title_dir = title_dir.join(&tid_low);
        safe_create_dir(&title_dir)?;
        // Create an empty "data" dir if it doesn't exist.
        safe_create_dir(&title_dir.join("data"))?;
        title_dir = title_dir.join("content");
        // Delete any existing installed content/the current TMD.
        if title_dir.exists() {
            fs::remove_dir_all(&title_dir)?;
        }
        fs::create_dir(&title_dir)?;
        fs::write(title_dir.join("title.tmd"), title.content.to_bytes()?)?;
        for i in 0..title.content.content_records.borrow().len() {
            if matches!(title.content.content_records.borrow()[i].content_type, tmd::ContentType::Normal) {
                let content_path = title_dir.join(format!("{:08X}.app", title.content.content_records.borrow()[i].content_id).to_ascii_lowercase());
                fs::write(content_path, title.get_content_by_index(i)?)?;
            }
        }
        // Shared content needs to be installed to /shared1/, with incremental names decided by
        // the records in /shared1/content.map.
        // Start by checking for a map and loading it if it exists, so that we know what shared
        // content is already installed.
        let content_map_path = self.emunand_dirs["shared1"].join("content.map");
        let mut content_map = if content_map_path.exists() {
            content::SharedContentMap::from_bytes(&fs::read(&content_map_path)?)?
        } else {
            content::SharedContentMap::new()
        };
        for i in 0..title.content.content_records.borrow().len() {
            if matches!(title.content.content_records.borrow()[i].content_type, tmd::ContentType::Shared) {
                if let Some(file_name) = content_map.add(&title.content.content_records.borrow()[i].content_hash)? {
                    let content_path = self.emunand_dirs["shared1"].join(format!("{}.app", file_name.to_ascii_lowercase()));
                    fs::write(content_path, title.get_content_by_index(i)?)?;
                }
            }
        }
        fs::write(&content_map_path, content_map.to_bytes()?)?;
        // The "footer" (officially "meta") is installed to /meta/<tid_high>/<tid_low>/title.met.
        let meta_data = title.meta();
        if !meta_data.is_empty() {
            let mut meta_dir = self.emunand_dirs["meta"].join(&tid_high);
            safe_create_dir(&meta_dir)?;
            meta_dir = meta_dir.join(&tid_low);
            safe_create_dir(&meta_dir)?;
            fs::write(meta_dir.join("title.met"), meta_data)?;
        }
        // Finally, we need to update uid.sys (or create it if it doesn't exist) so that the newly
        // installed title will actually show up (at least for channels).
        let uid_sys_path = self.emunand_dirs["sys"].join("uid.sys");
        let mut uid_sys = if uid_sys_path.exists() {
            sys::UidSys::from_bytes(&fs::read(&uid_sys_path)?)?
        } else {
            sys::UidSys::new()
        };
        uid_sys.add(&title.tmd.title_id())?;
        fs::write(&uid_sys_path, &uid_sys.to_bytes()?)?;
        Ok(())
    }
}
