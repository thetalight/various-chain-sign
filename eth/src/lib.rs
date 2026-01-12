use alloy::{
    consensus::{EthereumTxEnvelope, SignableTransaction, TxEip4844Variant},
    network::{Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder},
    node_bindings::Anvil,
    primitives::{FixedBytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::{Signature, SignerSync, local::PrivateKeySigner},
};

#[test]
fn test_sign() {
    const PRIVATE_KEY_BYTES: [u8; 32] = [
        216, 166, 206, 234, 67, 115, 17, 206, 67, 244, 2, 74, 142, 138, 59, 3, 118, 156, 69, 148,
        111, 104, 216, 47, 49, 253, 0, 104, 186, 79, 60, 224,
    ];
    let signer = PrivateKeySigner::from_slice(&PRIVATE_KEY_BYTES).unwrap();

    let msg_hash = FixedBytes::from_slice(&[1u8; 32]);
    let s = signer.sign_hash_sync(&msg_hash).unwrap();

    let r = s.recover_address_from_prehash(&msg_hash).unwrap();
    assert_eq!(r, signer.address());

    assert_eq!(
        "74f51a3690a3f50ed813a9c68be84312abc50e5b97c6b07cccc7df19c8000c232a294312e635ce893b25e8fc56d7c5593a2bbc30b9f1517b8965a91530588fa41b",
        hex::encode(s.as_bytes())
    );
}

#[tokio::test]
async fn test_eth() {
    let anvil = Anvil::new().block_time(1).try_spawn().unwrap();

    let signer_alice: PrivateKeySigner = anvil.keys()[0].clone().into();
    let signer_bob: PrivateKeySigner = anvil.keys()[1].clone().into();

    let alice = signer_alice.address();
    let bob = signer_bob.address();

    let rpc_url = anvil.endpoint_url();
    let provider = ProviderBuilder::new()
        .wallet(signer_alice.clone())
        .connect_http(rpc_url.clone());

    let tx = TransactionRequest::default()
        .with_to(bob)
        .with_nonce(0)
        .with_chain_id(provider.get_chain_id().await.unwrap())
        .with_value(U256::from(100))
        .with_gas_limit(21_000)
        .with_max_priority_fee_per_gas(1_000_000_000)
        .with_max_fee_per_gas(20_000_000_000);

    let _tx_envelope = {
        let tx_unsigned = tx.clone().build_unsigned().unwrap();
        // tx_unsigned.set_chain_id_checked(1);

        //  let signature_hash = tx_unsigned.signature_hash();
        let rlp_encode = tx_unsigned.encoded_for_signing();
        let signature_hash = keccak256(rlp_encode);

        let signature = signer_alice.sign_hash_sync(&signature_hash).unwrap();
        let tx_envelope_0: EthereumTxEnvelope<TxEip4844Variant> =
            tx_unsigned.clone().into_signed(signature).into();

        let wallet = EthereumWallet::from(signer_alice.clone());
        let tx_envelope_1 = <EthereumWallet as NetworkWallet<Ethereum>>::sign_transaction_from(
            &wallet,
            alice, // 地址只是用来索引
            tx_unsigned,
        )
        .await
        .unwrap();

        assert_eq!(tx_envelope_0, tx_envelope_1);

        tx_envelope_0
    };
}

#[test]
fn test_sign_n60() {
    let bytes =
        hex::decode(b"57979955d10883aaa7a0ccd4347211aac4044fdb441f17e767578e862945c17b").unwrap();
    let signer = PrivateKeySigner::from_slice(&bytes).unwrap();
    assert_eq!(
        signer.address().to_string(),
        "0xa652886Cbd45B63C2F3382066C7CB378E66D280b"
    );

    // soft
    let data =
        hex::decode(b"71d027c296147783637ed2c26544bafef53b4cef1ab8250830175b149f38c5e5").unwrap();
    let msg_hash = keccak256(data);
    let s = signer.sign_hash_sync(&msg_hash).unwrap();
    println!("signature:{:?}", s.as_bytes());

    // n60
    let sign_bytes = hex::decode(b"66789af020efbcb4507ee1b0a3cfc2460ad00703342817287f6c5a3c92eae7cc3514c8ba36c6bc1ba0c4fd79bd57938088b8bce6bf3f31c5e3f571cc718f97c71c").unwrap();
    let s: Signature = Signature::try_from(sign_bytes.as_slice()).unwrap();
    let expect = s.recover_address_from_prehash(&msg_hash).unwrap();
    assert_eq!(expect, signer.address());
}
