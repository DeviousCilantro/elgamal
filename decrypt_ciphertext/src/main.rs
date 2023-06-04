use std::io;
use std::io::Write;
use rug::Integer;


fn decrypt_ciphertext(ciphertext: (Integer, Integer), sk: &Integer, q: &Integer) -> Integer {
    let (c1, c2) = ciphertext;
    let theta = c1.secure_pow_mod(sk, q);
    ((c2 % q.clone()) * theta.invert(q).unwrap()) % q.clone()
}

fn main() {
    print!("Enter the ciphertext (c1, c2): ");
    print!("\nEnter c1: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let c1 = Integer::from_str_radix(input, 10).unwrap();
    print!("Enter c2: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let c2 = Integer::from_str_radix(input, 10).unwrap();
    print!("\nEnter the secret key (alpha): ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let sk = Integer::from_str_radix(input, 10).unwrap();
    print!("\nEnter q: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let q = Integer::from_str_radix(input, 10).unwrap();
    let ciphertext = (c1, c2);
    let output_plaintext = decrypt_ciphertext(ciphertext, &sk, &q);
    let output_plaintext = format!("{:X}", &output_plaintext);
    println!("\nDecrypted plaintext: {}", String::from_utf8(hex::decode(output_plaintext).unwrap()).unwrap());
}
