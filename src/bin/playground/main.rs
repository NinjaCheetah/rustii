// Sample file for testing rustii library stuff.

use std::fs;
use rustii::title::{tmd, ticket, content, crypto, wad};

fn main() {
    let data = fs::read("sm.wad").unwrap();
    let wad = wad::WAD::from_bytes(&data).unwrap();
    println!("size of tmd: {:?}", wad.tmd().len());
    let tmd = tmd::TMD::from_bytes(&wad.tmd()).unwrap();
    println!("num content records: {:?}", tmd.content_records.len());
    println!("first record data: {:?}", tmd.content_records.first().unwrap());
    assert_eq!(wad.tmd(), tmd.to_bytes().unwrap());

    let tik = ticket::Ticket::from_bytes(&wad.ticket()).unwrap();
    println!("title version from ticket is: {:?}", tik.title_version);
    println!("title key (enc): {:?}", tik.title_key);
    println!("title key (dec): {:?}", tik.dec_title_key());
    assert_eq!(wad.ticket(), tik.to_bytes().unwrap());

    let content_region = content::ContentRegion::from_bytes(&wad.content(), tmd.content_records).unwrap();
    assert_eq!(wad.content(), content_region.to_bytes().unwrap());
    println!("content OK");

    let content_dec = content_region.get_content_by_index(0, tik.dec_title_key()).unwrap();
    println!("content dec from index: {:?}", content_dec);

    let content = content_region.get_enc_content_by_index(0).unwrap();
    assert_eq!(content, crypto::encrypt_content(&content_dec, tik.dec_title_key(), 0, content_region.content_records[0].content_size));
    println!("content re-encrypted OK");

    println!("wad header: {:?}", wad.header);

    let repacked = wad.to_bytes().unwrap();
    assert_eq!(repacked, data);
    println!("wad packed OK");
}
