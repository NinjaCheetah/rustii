// Sample file for testing rustii library stuff.

use std::fs;
use rustii::title::{wad, cert};
use rustii::title;

fn main() {
    let data = fs::read("sm.wad").unwrap();
    let title = title::Title::from_bytes(&data).unwrap();
    println!("Title ID from WAD via Title object: {}", hex::encode(title.tmd.title_id));
    
    let wad = wad::WAD::from_bytes(&data).unwrap();
    println!("size of tmd: {:?}", wad.tmd().len());
    println!("num content records: {:?}", title.tmd.content_records.len());
    println!("first record data: {:?}", title.tmd.content_records.first().unwrap());
    println!("TMD is fakesigned: {:?}",title.tmd.is_fakesigned());
    
    println!("title version from ticket is: {:?}", title.ticket.title_version);
    println!("title key (enc): {:?}", title.ticket.title_key);
    println!("title key (dec): {:?}", title.ticket.dec_title_key());
    println!("ticket is fakesigned: {:?}", title.ticket.is_fakesigned());
    
    println!("title is fakesigned: {:?}", title.is_fakesigned());
    
    println!("wad header: {:?}", wad.header);
    
    let cert_chain = &title.cert_chain;
    println!("cert chain OK");
    let result = cert::verify_ca_cert(&cert_chain.ca_cert()).unwrap();
    println!("CA cert {} verified successfully: {}", cert_chain.ca_cert().child_cert_identity(), result);
    
    let result = cert::verify_child_cert(&cert_chain.ca_cert(), &cert_chain.tmd_cert()).unwrap();
    println!("TMD cert {} verified successfully: {}", cert_chain.tmd_cert().child_cert_identity(), result);
    let result = cert::verify_tmd(&cert_chain.tmd_cert(), &title.tmd).unwrap();
    println!("TMD verified successfully: {}", result);
    
    let result = cert::verify_child_cert(&cert_chain.ca_cert(), &cert_chain.ticket_cert()).unwrap();
    println!("Ticket cert {} verified successfully: {}", cert_chain.ticket_cert().child_cert_identity(), result);
    let result = cert::verify_ticket(&cert_chain.ticket_cert(), &title.ticket).unwrap();
    println!("Ticket verified successfully: {}", result);
    
    let result = title.verify().unwrap();
    println!("full title verified successfully: {}", result);
    // let mut u8_archive = u8::U8Archive::from_bytes(&fs::read("00000001.app").unwrap()).unwrap();
    // println!("files and dirs counted: {}", u8_archive.node_tree.borrow().count());
    // fs::write("outfile.arc", u8_archive.to_bytes().unwrap()).unwrap();
    // println!("re-written");
}
