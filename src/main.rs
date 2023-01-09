use data_encoding::HEXUPPER;
use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::{digest, pbkdf2, rand};
use std::num::NonZeroU32;
fn main() -> Result<(), Unspecified> {
    type CREDENTIAL = [u8; CREDENTIAL_LEN];
    // hash length
    const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
    static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
    let rng = rand::SystemRandom::new();
    let mut salt = [0u8; CREDENTIAL_LEN];
    rng.fill(&mut salt)?;
    let password = "Humans Are Dead. We used poisonous gases, to poison their asses";
    let mut pbkdf2_hash: CREDENTIAL = [0u8; CREDENTIAL_LEN];
    let pbkdf2_iterations = NonZeroU32::new(100_00).unwrap();

    // create hash
    pbkdf2::derive(
        PBKDF2_ALG,
        pbkdf2_iterations,
        &salt,
        password.as_bytes(),
        &mut pbkdf2_hash,
    );

    println!("Salt: {}", HEXUPPER.encode(&salt));
    println!("PBKDF2 hash: {}", HEXUPPER.encode(&pbkdf2_hash));

    Ok(())
}
