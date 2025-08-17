use mpc_api::elliptic_curve::{ECDigitalSignature, ECDSA, SimpleEC, EllipticCurve};

fn main() {
    println!("=== ECDSA Debug Tool ===");
    
    match debug_ecdsa() {
        Ok(()) => println!("Debug completed successfully"),
        Err(e) => println!("Debug failed: {}", e),
    }
}

fn debug_ecdsa() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n1. Testing curve parameters...");
    let params = SimpleEC::params();
    println!("Curve parameters: a={}, b={}, p={}, n={}", params.a, params.b, params.p, params.n);
    println!("Generator point: x={}, y={}, is_infinity={}", params.g.x, params.g.y, params.g.is_infinity);
    
    // Check if generator is on curve
    let is_on_curve = SimpleEC::is_on_curve(&params.g);
    println!("Generator is on curve: {}", is_on_curve);
    
    println!("\n2. Testing keypair generation...");
    let (private_key, public_key) = ECDigitalSignature::generate_keypair()?;
    println!("Private key: {}", private_key);
    println!("Public key: x={}, y={}, is_infinity={}", public_key.x, public_key.y, public_key.is_infinity);
    
    // Check if public key is on curve
    let is_on_curve = SimpleEC::is_on_curve(&public_key);
    println!("Public key is on curve: {}", is_on_curve);
    
    println!("\n3. Testing signature creation...");
    let message_hash = 12345u64;
    println!("Message hash: {}", message_hash);
    
    let signature = ECDigitalSignature::sign(private_key, message_hash)?;
    println!("Signature: r={}, s={}", signature.r, signature.s);
    
    println!("\n4. Testing signature verification...");
    let verification = ECDigitalSignature::verify(&public_key, message_hash, &signature)?;
    println!("Verification result: {}", verification);
    
    if !verification {
        println!("\n=== VERIFICATION FAILED - DEBUGGING ===");
        
        // Let's manually step through verification
        let params = SimpleEC::params();
        println!("Using curve params: n={}", params.n);
        
        // Check signature bounds
        println!("Checking signature bounds:");
        println!("r={} in range [1, {}): {}", signature.r, params.n, signature.r > 0 && signature.r < params.n);
        println!("s={} in range [1, {}): {}", signature.s, params.n, signature.s > 0 && signature.s < params.n);
        
        // Try another verification attempt
        println!("Attempting verification again...");
    }
    
    Ok(())
}