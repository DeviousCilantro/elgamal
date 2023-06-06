use rug::Integer;
use num_primes::Generator;
use ring::rand::{SystemRandom, SecureRandom};

fn generate_keypair() -> ((String, String, String), String) {
    let rand = SystemRandom::new();
    println!("\nGenerating keypair...");
    let p = Integer::from_str_radix(&Generator::safe_prime(512).to_string(), 10).unwrap();
    let q = (p.clone() - Integer::from(1)) / 2;
    let mut a;
    let g;
    loop {
        a = random_integer(&rand, p.clone());
        let asq = a.clone() * a.clone();
        if (asq - Integer::from(1)) % p.clone() != 0 {
               g = Integer::secure_pow_mod(a, &Integer::from(2), &q);
            break;
        }
    }
    let alpha = random_integer(&rand, q.clone());
    let h = g.clone().secure_pow_mod(&alpha, &q);
    ((base64::encode(q.to_string()), base64::encode(g.to_string()), base64::encode(h.to_string())), base64::encode(alpha.to_string()))
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
    let ((q, g, h), alpha) = generate_keypair();
    println!("\nPublic key: (q, g, h)");
    println!("q: {q}");
    println!("g: {g}");
    println!("h: {h}");
    println!("\nSecret key: {alpha}");
}
