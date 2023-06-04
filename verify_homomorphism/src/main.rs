use std::io;
use std::io::Write;
use rug::{Integer, rand};
use num_primes::Generator;


fn generate_keypair() -> ((Integer, Integer, Integer), Integer) {
    let p = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let q = (p.clone() - Integer::from(1)) / 2;
    let mut a;
    let g;
    let mut rand = rand::RandState::new();
    loop {
        a = p.clone().random_below(&mut rand);
        let asq = a.clone() * a.clone();
        if (asq - Integer::from(1)) % p.clone() != 0 {
               g = Integer::secure_pow_mod(a, &Integer::from(2), &q);
            break;
        }
    }
    let alpha = q.clone().random_below(&mut rand);
    let h = g.clone().secure_pow_mod(&alpha, &q);
    ((q, g, h), alpha)
}

fn encrypt_plaintext(plaintext: Integer, pk: (Integer, Integer, Integer)) -> (Integer, Integer) {
    let (q, g, h) = pk;
    let mut c1 = Integer::new();
    let mut c2 = Integer::new();
    if plaintext >= 0 && plaintext < q {
        let mut rand = rand::RandState::new();
        let r = q.clone().random_below(&mut rand);
        c1 = g.secure_pow_mod(&r, &q);
        c2 = ((plaintext % q.clone()) * h.secure_pow_mod(&r, &q)) % q.clone();
    }
    (c1, c2)
}

fn decrypt_ciphertext(ciphertext: (Integer, Integer), sk: &Integer, q: &Integer) -> Integer {
    let (c1, c2) = ciphertext;
    let theta = c1.secure_pow_mod(sk, q);
    ((c2 % q.clone()) * theta.invert(q).unwrap()) % q.clone()
}

fn exponential_elgamal(plaintext: &Integer, pk: (Integer, Integer, Integer)) -> (Integer, Integer) {
    let (q, g, h) = pk;
    let mut c1 = Integer::new();
    let mut c2 = Integer::new();
    if *plaintext >= 0 && *plaintext < q {
        let mut rand = rand::RandState::new();
        let r = q.clone().random_below(&mut rand);
        c1 = g.clone().secure_pow_mod(&r, &q);
        c2 = (g.secure_pow_mod(plaintext, &q) * h.secure_pow_mod(&r, &q)) % q.clone();
    }
    (c1, c2)
}

fn verify_homomorphism(m1: &Integer, m2: &Integer, pk: (Integer, Integer, Integer), sk: &Integer) {
    let (q, g, _) = pk.clone();
    let sum = (m1.clone() + m2.clone()) % q.clone();
    let product = (m1.clone() * m2.clone()) % q.clone();
    let c1 = encrypt_plaintext(m1.clone(), pk.clone());
    let c2 = encrypt_plaintext(m2.clone(), pk.clone());
    let c3 = exponential_elgamal(m1, pk.clone());
    let c4 = exponential_elgamal(m2, pk);
    assert_eq!(decrypt_ciphertext(c1.clone(), sk, &q), *m1, "Correctness not verified");
    assert_eq!(decrypt_ciphertext(c2.clone(), sk, &q), *m2, "Correctness not verified");
    assert_eq!(decrypt_ciphertext(((c1.clone().0 * c2.clone().0) % q.clone(), (c1.1 * c2.1) % q.clone()), sk, &q), product,  "Not multiplicatively homomorphic");
    assert_eq!(decrypt_ciphertext(((c3.clone().0 * c4.clone().0) % q.clone(), (c3.1 * c4.1) % q.clone()), sk, &q), g.secure_pow_mod(&sum, &q),  "Not additively homomorphic");
    println!("Verified (additive + multiplicative) homomorphism and correctness.");
}

fn main() {
    println!("Enter two strings to verify additive homomorphism.");
    let mut input = String::new();
    print!("Enter m1: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let m1 = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let mut input = String::new();
    print!("Enter m2: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let input = input.trim();
    let m2 = Integer::from_str_radix(&hex::encode(input), 16).unwrap();
    let (pk, sk) = generate_keypair();
    verify_homomorphism(&m1, &m2, pk, &sk);
}
