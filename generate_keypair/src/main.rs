use rug::{Integer, rand};
use num_primes::Generator;

fn generate_keypair() -> ((String, String, String), String) {
    println!("\nGenerating keypair...");
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
    ((base64::encode(q.to_string()), base64::encode(g.to_string()), base64::encode(h.to_string())), base64::encode(alpha.to_string()))
}

fn main() {
    let ((q, g, h), alpha) = generate_keypair();
    println!("\nPublic key: (q, g, h)");
    println!("q: {q}");
    println!("g: {g}");
    println!("h: {h}");
    println!("\nSecret key: {alpha}");
}
