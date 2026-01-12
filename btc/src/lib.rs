use std::{io::Write, str::FromStr};

use bitcoin::{
    Address, PrivateKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    block::Version,
    hashes::Hash,
    key::Secp256k1 as btc_secp256k1,
    sighash::{EcdsaSighashType, LegacySighash, SighashCache},
};
use secp256k1::{Message, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Deserialize, Serialize)]
struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
}

#[test]
fn test_btc_sign() {
    const PRIVATE_KEY_BYTES: [u8; 32] = [
        216, 166, 206, 234, 67, 115, 17, 206, 67, 244, 2, 74, 142, 138, 59, 3, 118, 156, 69, 148,
        111, 104, 216, 47, 49, 253, 0, 104, 186, 79, 60, 224,
    ];
    let secp = Secp256k1::new();

    let sk = secp256k1::SecretKey::from_slice(&PRIVATE_KEY_BYTES).unwrap();
    let pk = sk.public_key(&secp);

    let msg = Message::from_digest([1u8; 32]);
    let sig = secp.sign_ecdsa(&msg, &sk);
    secp.verify_ecdsa(&msg, &sig, &pk).unwrap();

    // 签名长度 64 字节
    assert_eq!(
        "74f51a3690a3f50ed813a9c68be84312abc50e5b97c6b07cccc7df19c8000c232a294312e635ce893b25e8fc56d7c5593a2bbc30b9f1517b8965a91530588fa4",
        hex::encode(&sig.serialize_compact())
    );
}

#[test]
fn test_btc_tx() {
    const PRIVATE_KEY_BYTES: [u8; 32] = [
        216, 166, 206, 234, 67, 115, 17, 206, 67, 244, 2, 74, 142, 138, 59, 3, 118, 156, 69, 148,
        111, 104, 216, 47, 49, 253, 0, 104, 186, 79, 60, 224,
    ];

    let privkey = PrivateKey::from_slice(&PRIVATE_KEY_BYTES, bitcoin::Network::Bitcoin).unwrap();
    let secp = btc_secp256k1::new();
    let pubkey = privkey.public_key(&secp);
    let addr = Address::p2pkh(&pubkey, bitcoin::Network::Bitcoin);
    println!("Address: {:?}", addr);

    let utxo_json = r##"
    { 
        "txid":"a97f9bb61da5650eaf7e75042d3c30fcb9582fd0aae4f97621ea7d0601486571",
        "vout":0,
        "value":184061 
    }
    "##;
    let utxo = serde_json::from_str::<Utxo>(&utxo_json).unwrap();

    let txin = TxIn {
        previous_output: bitcoin::OutPoint {
            txid: Txid::from_str(&utxo.txid).unwrap(),
            vout: utxo.vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };

    let fee = 500;
    let txout = TxOut {
        value: utxo.value - fee,
        script_pubkey: addr.script_pubkey(), // send to the same address
    };

    let raw_tx = Transaction {
        version: Version::ONE.to_consensus(),
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    let cash = SighashCache::new(&raw_tx);
    let sig_hash = cash
        .legacy_signature_hash(0, &addr.script_pubkey(), EcdsaSighashType::All.to_u32())
        .unwrap();
    println!("sig_hash:{:?}", sig_hash.to_string());

    {
        let expect_vec = vec![
            1, 0, 0, 0, 1, 113, 101, 72, 1, 6, 125, 234, 33, 118, 249, 228, 170, 208, 47, 88, 185,
            252, 48, 60, 45, 4, 117, 126, 175, 14, 101, 165, 29, 182, 155, 127, 169, 0, 0, 0, 0,
            25, 118, 169, 20, 53, 236, 84, 188, 176, 54, 141, 98, 225, 113, 71, 69, 27, 96, 145,
            98, 62, 82, 54, 112, 136, 172, 255, 255, 255, 255, 1, 9, 205, 2, 0, 0, 0, 0, 0, 25,
            118, 169, 20, 53, 236, 84, 188, 176, 54, 141, 98, 225, 113, 71, 69, 27, 96, 145, 98,
            62, 82, 54, 112, 136, 172, 0, 0, 0, 0, 1, 0, 0, 0,
        ];
        let hex = hex::encode(&expect_vec);
        println!("expect_vec:{:?}", hex);
        let mut vec = Vec::new();
        let resut = cash.legacy_encode_signing_data_to(
            &mut vec,
            0,
            &addr.script_pubkey(),
            EcdsaSighashType::All.to_u32(),
        );
        assert_eq!(vec, expect_vec);
        let is_bug = resut.is_sighash_single_bug().unwrap();
        println!("is_bug:{:?}", is_bug);
        println!("unsign_hash_len:{:?}", vec.len());
        println!("unsign_hash:{:?}", vec);

        let mut enc = LegacySighash::engine();
        let len = enc.write(&vec).unwrap();
        println!("write len:{:?}", len);

        let sig_hash0 = LegacySighash::from_engine(enc); // double hash
        println!("sig_hash:{:?}", sig_hash.to_string());
        assert_eq!(sig_hash, sig_hash0);

        use sha2::Digest;
        let h1 = Sha256::digest(&vec); // double hash
        let h2 = Sha256::digest(&h1);
        assert_eq!(sig_hash, LegacySighash::from_slice(&h2).unwrap());
    }

    let msg = bitcoin::secp256k1::Message::from_slice(sig_hash.as_byte_array()).unwrap();
    let sig_bytes = "a7ef567ba9df658125e1faaf20df8f41822ba999b1b9f09a1b0fe8a4b7b5d97410b6fd5c05129f216ad500576b147353f52343957dc5ed398bd1ee8ab8aa8375";
    let mut sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(
        hex::decode(sig_bytes).unwrap().as_slice(),
    )
    .unwrap();
    sig.normalize_s();
    println!("sig:{:?}", hex::encode(&sig.serialize_compact()));
    secp.verify_ecdsa(&msg, &sig, &pubkey.inner).unwrap();
}
