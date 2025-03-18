use std::fs;
use rustii::title::{tmd, ticket, content};

fn main() {
    let data = fs::read("title.tmd").unwrap();
    let tmd = tmd::TMD::from_bytes(&data).unwrap();
    println!("num content records: {:?}", tmd.content_records.len());
    println!("first record data: {:?}", tmd.content_records.first().unwrap());
    assert_eq!(data, tmd.to_vec().unwrap());
    
    let data = fs::read("tik").unwrap();
    let tik = ticket::Ticket::from_bytes(&data).unwrap();
    println!("title version from ticket is: {:?}", tik.title_version);
    println!("title key (enc): {:?}", tik.title_key);
    println!("title key (dec): {:?}", tik.dec_title_key());
    assert_eq!(data, tik.to_vec().unwrap());
    
    let data = fs::read("content-blob").unwrap();
    let content_region = content::ContentRegion::from_bytes(&data, tmd.content_records).unwrap();
    assert_eq!(data, content_region.to_bytes().unwrap());
    println!("content OK");
    
    let content_dec = content_region.get_content_by_index(0, tik.dec_title_key()).unwrap();
    println!("content dec from index: {:?}", content_dec);
    
    let content = content_region.get_content_by_cid(150, tik.dec_title_key()).unwrap();
    println!("content dec from cid: {:?}", content);
}
