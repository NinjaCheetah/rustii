use std::fs;
use rustii::title::{tmd, ticket, crypto};

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
    
    
    assert_eq!(tik.title_key, crypto::encrypt_title_key(tik.dec_title_key(), tik.common_key_index, tik.title_id));
    println!("re-encrypted key matched");
}
