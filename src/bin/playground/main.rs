// Sample file for testing rustii library stuff.

use std::fs;
use rustii::title::{content, crypto, wad};
use rustii::title;

fn main() {
    let data = fs::read("boot2.wad").unwrap();
    let mut title = title::Title::from_bytes(&data).unwrap();
    println!("Title ID from WAD via Title object: {}", hex::encode(title.tmd.title_id));
    
    let wad = wad::WAD::from_bytes(&data).unwrap();
    println!("size of tmd: {:?}", wad.tmd().len());
    println!("num content records: {:?}", title.tmd.content_records.len());
    println!("first record data: {:?}", title.tmd.content_records.first().unwrap());
    if !title.tmd.is_fakesigned() {
        title.tmd.fakesign().unwrap();
    }
    println!("TMD is fakesigned: {:?}",title.tmd.is_fakesigned());

    println!("title version from ticket is: {:?}", title.ticket.title_version);
    println!("title key (enc): {:?}", title.ticket.title_key);
    println!("title key (dec): {:?}", title.ticket.dec_title_key());
    if !title.ticket.is_fakesigned() {
        title.ticket.fakesign().unwrap();
    }
    println!("ticket is fakesigned: {:?}", title.ticket.is_fakesigned());
    
    println!("title is fakesigned: {:?}", title.is_fakesigned());

    let content_region = content::ContentRegion::from_bytes(&wad.content(), title.tmd.content_records).unwrap();
    assert_eq!(wad.content(), content_region.to_bytes().unwrap());
    println!("content OK");

    let content_dec = content_region.get_content_by_index(0, title.ticket.dec_title_key()).unwrap();
    println!("content dec from index: {:?}", content_dec);

    let content = content_region.get_enc_content_by_index(0).unwrap();
    assert_eq!(content, crypto::encrypt_content(&content_dec, title.ticket.dec_title_key(), 0, content_region.content_records[0].content_size));
    println!("content re-encrypted OK");

    println!("wad header: {:?}", wad.header);
}
