use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, PublicKeyParts};
use rsa::pkcs1::{ToRsaPrivateKey, ToRsaPublicKey};
use std::env;
use std::fs::File;
use std::io::Write;

fn main() {
    // 引数からターゲットの文字列を取得
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <target_string>", args[0]);
        std::process::exit(1);
    }
    let target_string = &args[1];
    println!("Target {}", target_string);

    let mut attempt_count = 0;

    loop {
        attempt_count += 1;
        println!("{}: Generating RSA-4096 key pair...", attempt_count);

        // ランダムなRSA-4096鍵ペアを生成する
        let mut rng = OsRng;
        let bits = 4096;
        let private_key = match RsaPrivateKey::new(&mut rng, bits) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("Failed to generate a key: {:?}", e);
                continue;
            }
        };
        let public_key = RsaPublicKey::from(&private_key);
        println!("Attempt {}: Key pair generated", attempt_count);

        // 公開鍵をPEM形式に変換
        let public_pem = match public_key.to_pkcs1_pem() {
            Ok(pem) => pem,
            Err(e) => {
                eprintln!("Failed to convert public key to PEM: {:?}", e);
                continue;
            }
        };
        println!("Attempt {}: Public key PEM extracted", attempt_count);
        // PEM形式の公開鍵にターゲットの文字列が含まれているかチェックする
        if public_pem.contains(target_string) {
            println!("Match found on attempt {}!", attempt_count);
            println!("Generated RSA-4096 key pair where public key PEM contains the target string.");

            // 鍵ペアを保存するかどうか対話式に
            println!("Do you want to save the key pair? (yes/no)");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).expect("Failed to read line");
            if input.trim().eq_ignore_ascii_case("yes") {
                save_key_pair(&private_key, &public_key);
            }
            break;
        } else {
            println!("Attempt {}: No match found", attempt_count);
        }
    }
}

fn save_key_pair(private_key: &RsaPrivateKey, public_key: &RsaPublicKey) {
    let private_pem = private_key.to_pkcs1_pem().expect("failed to convert private key to PEM");
    let public_pem = public_key.to_pkcs1_pem().expect("failed to convert public key to PEM");

    let mut private_file = File::create("private_key.pem").expect("failed to create private key file");
    private_file.write_all(private_pem.as_bytes()).expect("failed to write private key");

    let mut public_file = File::create("public_key.pem").expect("failed to create public key file");
    public_file.write_all(public_pem.as_bytes()).expect("failed to write public key");

    println!("Key pair saved to 'private_key.pem' and 'public_key.pem'");
}

