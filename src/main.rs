use std::env;
use std::fs::{self, File};
use std::io::{Write};
use aes::{Aes128, NewBlockCipher}; // Importer NewBlockCipher
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use generic_array::{GenericArray, typenum::U16}; // Importer GenericArray et typenum

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: cargo run -- --crypt --file [file] --password [password]");
        eprintln!("Or: cargo run -- --decrypt --file [file] --redrose [key_file]");
        return;
    }

    let mode = &args[1];
    let file_path = &args[3];
    let password = &args[4];

    match mode.as_str() {
        "--crypt" => encrypt_file(file_path, password),
        "--decrypt" => decrypt_file(file_path, &args[5]),
        _ => eprintln!("Invalid mode. Use --crypt or --decrypt."),
    }
}

fn encrypt_file(file_path: &str, password: &str) {
    let file_content = fs::read(file_path).expect("Unable to read file");
    let key = generate_key(password);

    // Chiffrement du contenu avec AES
    let iv = GenericArray::<u8, U16>::from_slice(&key[0..16]); // Vecteur d'initialisation (IV)

    // Créer un GenericArray pour la clé
    let key_array = GenericArray::from_slice(&key); // Convertir la clé en GenericArray

    let cipher = Aes128Cbc::new(Aes128::new(&key_array), iv);

    let encrypted_data = cipher.encrypt_vec(&file_content);

    // Écrire le fichier chiffré
    let encrypted_file_path = format!("{}.encrypted", file_path);
    let mut output_file = File::create(&encrypted_file_path).unwrap();
    output_file.write_all(&encrypted_data).unwrap();

    // Écrire la clé dans un fichier .redrose
    let key_file_path = format!("{}.redrose", file_path);
    let mut key_file = File::create(&key_file_path).unwrap();
    key_file.write_all(&key).unwrap();

    println!("File encrypted as {} and key saved as {}", encrypted_file_path, key_file_path);
}

fn decrypt_file(encrypted_file_path: &str, key_file_path: &str) {
    let encrypted_data = fs::read(encrypted_file_path).expect("Unable to read encrypted file");

    // Lire la clé depuis le fichier .redrose
    let key = fs::read(key_file_path).expect("Unable to read key file");

    // Déchiffrement du contenu chiffré avec AES
    let iv = GenericArray::<u8, U16>::from_slice(&key[0..16]); // Vecteur d'initialisation (IV)

    // Créer un GenericArray pour la clé
    let key_array = GenericArray::from_slice(&key); // Convertir la clé en GenericArray

    let cipher = Aes128Cbc::new(Aes128::new(&key_array), iv);

    let decrypted_data = cipher.decrypt_vec(&encrypted_data).expect("Decryption failed");

    // Écrire le fichier reconstruit
    let reconstructed_file_path = format!("{}.reconstructed", encrypted_file_path);
    let mut output_file = File::create(&reconstructed_file_path).unwrap();
    output_file.write_all(&decrypted_data).unwrap();

    println!("File decrypted and saved as {}", reconstructed_file_path);
}

fn generate_key(password: &str) -> Vec<u8> {
    // Générer une clé basée sur le mot de passe (simple hash pour cet exemple)
    let mut key = vec![0u8; 16];
    for (i, byte) in password.bytes().enumerate() {
        key[i % 16] ^= byte; // Simple XOR pour la démonstration
    }
    key
}
