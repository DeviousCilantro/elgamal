use std::io;
use std::io::Write;
use rug::Integer;
use ring::rand::{SystemRandom, SecureRandom};

fn encrypt_plaintext(plaintext: Integer, pk: (Integer, Integer, Integer)) -> (Integer, Integer) {
    let rand = SystemRandom::new();
    let (q, g, h) = pk;
    let mut c1 = Integer::new();
    let mut c2 = Integer::new();
    if plaintext >= 0 && plaintext < q {
        let r = random_integer(&rand, q.clone());
        c1 = g.secure_pow_mod(&r, &q);
        c2 = ((plaintext % q.clone()) * h.secure_pow_mod(&r, &q)) % q.clone();
    }
    (c1, c2)
}

fn random_integer(rng: &SystemRandom, range: Integer) -> Integer {
    loop {
        let mut bytes = vec![0; ((range.significant_bits() + 7) / 8) as usize];
        rng.fill(&mut bytes).unwrap();
        let num = Integer::from_digits(&bytes, rug::integer::Order::Lsf);
        if num < range {
            return num;
        }
    }
}


fn main() {
    print!("Enter the plaintext: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let input_plaintext = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    println!("\nEnter the public key (q, g, h): ");
    print!("Enter q: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let q = Integer::from_str_radix(input, 10).unwrap();
    print!("Enter g: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let g = Integer::from_str_radix(input, 10).unwrap();
    print!("Enter h: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    let h = Integer::from_str_radix(input, 10).unwrap();
    let pk = (q, g, h);
    let (c1, c2) = encrypt_plaintext(input_plaintext, pk.clone());
    println!("\nEncrypted ciphertext: (c1, c2)");
    println!("c1 = {}", base64::encode(c1.to_string()));
    println!("c2 = {}", base64::encode(c2.to_string()));
}
