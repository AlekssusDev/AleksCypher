use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use aes_gcm::aes::cipher::generic_array::GenericArray;
use aes_gcm::aes::cipher::typenum::U12;
use argon2::{Argon2, Algorithm, Params, Version};
use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

// -------------------- Constants --------------------
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const MANIFEST_LEN: usize = 40; // 8(len)+8(ts)+16(uuid)+8(steps)
const VERSION: u8 = 3;

const FLAG_ANTI_REPLAY: u8 = 0b0000_0001;
const FLAG_PADDING: u8 = 0b0000_0010;
const PADDING_LEVEL_MASK: u8 = 0b0000_1100;

const MIN_TIME_COST: u32 = 16;
const MAX_TIME_COST: u32 = 40;
const MIN_MEM_COST: u32 = 256 * 1024;
const MAX_MEM_COST: u32 = 512 * 1024;
const PARALLELISM: u32 = 2;

const GOOGOL_TIERS_ECONOMY: [usize; 8] = [16*1024, 32*1024, 64*1024, 128*1024, 256*1024, 512*1024, 1*1024*1024, 2*1024*1024];
const GOOGOL_TIERS_STANDARD: [usize; 8] = [64*1024, 128*1024, 256*1024, 512*1024, 1*1024*1024, 2*1024*1024, 4*1024*1024, 8*1024*1024];
const GOOGOL_TIERS_PARANOID: [usize; 8] = [1*1024*1024, 2*1024*1024, 4*1024*1024, 8*1024*1024, 16*1024*1024, 32*1024*1024, 64*1024*1024, 128*1024*1024];

// -------------------- Errors --------------------
#[derive(Debug)]
pub enum CryptoError {
    IoError(io::Error),
    DecryptionError,
    InvalidFormat,
    ReplayDetected,
    Argon2Error(String),
}

impl From<io::Error> for CryptoError {
    fn from(e: io::Error) -> Self { CryptoError::IoError(e) }
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::IoError(e) => write!(f, "IO error: {}", e),
            CryptoError::DecryptionError => write!(f, "Invalid password or corrupted file"),
            CryptoError::InvalidFormat => write!(f, "File is too short or malformed"),
            CryptoError::ReplayDetected => write!(f, "Replay attack detected (old file version)"),
            CryptoError::Argon2Error(e) => write!(f, "Key derivation error: {}", e),
        }
    }
}

// -------------------- Googol Parameters --------------------
fn googol_parameters(password: &[u8], salt: &[u8]) -> (u32, u32) {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    let hash = hasher.finalize();
    let seed = u64::from_be_bytes(hash[..8].try_into().unwrap());
    let m = (seed % 10) + 1;
    let n = ((seed >> 8) % 5) + 1;
    let factor = m.pow(n as u32) as u64;
    let time_cost = MIN_TIME_COST + (factor as u32 % (MAX_TIME_COST - MIN_TIME_COST + 1));
    let mem_step = 16 * 1024;
    let mem_cost = MIN_MEM_COST + ((factor >> 4) as u32 % ((MAX_MEM_COST - MIN_MEM_COST) / mem_step + 1)) * mem_step;
    (time_cost, mem_cost)
}

fn googol_padding_tier(password: &[u8], salt: &[u8], level: u8, original_len: usize) -> usize {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    let hash = hasher.finalize();
    let idx = hash[0] as usize % 8;
    let tiers = match level {
        1 => &GOOGOL_TIERS_STANDARD[..],
        2 => &GOOGOL_TIERS_PARANOID[..],
        _ => &GOOGOL_TIERS_ECONOMY[..],
    };
    let base = tiers[idx];
    ((original_len + base - 1) / base) * base
}

// -------------------- Ackermann RNG --------------------
fn crypto_ackermann(mut m: u32, mut n: u32) -> u32 {
    m &= 0x03; n &= 0x0F;
    let mut stack = Vec::with_capacity(1024);
    stack.push(m);
    let mut steps = 0u32;
    const MAX_STEPS: u32 = 50_000;
    while let Some(current_m) = stack.pop() {
        steps += 1;
        if steps > MAX_STEPS { return n ^ current_m ^ steps; }
        if current_m == 0 { n += 1; }
        else if n == 0 { stack.push(current_m - 1); n = 1; }
        else { stack.push(current_m - 1); stack.push(current_m); n -= 1; }
    }
    n
}

pub fn generate_ackermann_nonce(os_nonce: &[u8; 12]) -> GenericArray<u8, U12> {
    let mut final_nonce = [0u8; 12];
    for i in 0..6 {
        let byte_m = os_nonce[i*2]; let byte_n = os_nonce[i*2+1];
        let ack = crypto_ackermann(byte_m as u32, byte_n as u32);
        final_nonce[i*2] = byte_m ^ (ack & 0xFF) as u8;
        final_nonce[i*2+1] = byte_n ^ ((ack >> 8) & 0xFF) as u8;
    }
    GenericArray::clone_from_slice(&final_nonce)
}

// -------------------- Rayo Machine --------------------
#[inline(never)]
fn rayo_step_simulation(mut state: u64, i: u64) -> u64 {
    state = state.wrapping_add(i);
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    state
}

pub fn calibrate_rayo_steps() -> u64 {
    let mut state = 0x51A5705701234567u64;
    let test_iterations = 10_000_000u64;
    let start = std::time::Instant::now();
    for i in 0..test_iterations {
        state = rayo_step_simulation(state, i);
    }
    std::hint::black_box(state);
    let duration = start.elapsed().as_secs_f64().max(0.000001);
    let ops_per_second = (test_iterations as f64 / duration) as u64;
    let target = (ops_per_second as f64 * 0.75) as u64;
    target.clamp(10_000_000, 500_000_000)
}

fn rayo_expand_key(argon2_output: &[u8; KEY_LEN], steps: u64) -> (Zeroizing<[u8; KEY_LEN]>, Zeroizing<[u8; KEY_LEN]>) {
    let mut a = u64::from_be_bytes(argon2_output[0..8].try_into().unwrap());
    let mut b = u64::from_be_bytes(argon2_output[8..16].try_into().unwrap());
    for i in 0..steps {
        a = rayo_step_simulation(a, i);
        b = rayo_step_simulation(b, a);
    }
    let mut ikm = Vec::new();
    ikm.extend_from_slice(argon2_output);
    ikm.extend_from_slice(&a.to_be_bytes());
    ikm.extend_from_slice(&b.to_be_bytes());
    let h = Hkdf::<Sha256>::new(Some(b"aleksgoogol-v3"), &ikm);
    let mut ka = Zeroizing::new([0u8; KEY_LEN]);
    let mut kb = Zeroizing::new([0u8; KEY_LEN]);
    h.expand(b"aes-key", &mut *ka).expect("HKDF expand aes-key");
    h.expand(b"hmac-key", &mut *kb).expect("HKDF expand hmac-key");
    (ka, kb)
}

pub fn derive_keys(password: &[u8], salt: &[u8], rayo_steps: u64) -> Result<(Zeroizing<[u8; KEY_LEN]>, Zeroizing<[u8; KEY_LEN]>), CryptoError> {
    let (t, m) = googol_parameters(password, salt);
    let params = Params::new(m, t, PARALLELISM, Some(KEY_LEN)).map_err(|e| CryptoError::Argon2Error(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut ikm = [0u8; KEY_LEN];
    argon2.hash_password_into(password, salt, &mut ikm).map_err(|e| CryptoError::Argon2Error(e.to_string()))?;
    let (aes, hmac) = rayo_expand_key(&ikm, rayo_steps);
    ikm.zeroize();
    Ok((aes, hmac))
}

// -------------------- Encrypt --------------------
pub fn encrypt_file(
    input_path: &Path, output_path: &Path, password: &[u8],
    anti_replay: bool, padding_level: u8, rayo_steps: u64,
) -> Result<(), CryptoError> {
    let mut output_path = output_path.to_owned();
    if output_path.extension().map_or(true, |ext| ext != "acyph") {
        output_path.set_extension("acyph");
    }
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; SALT_LEN]; rng.fill(&mut salt);
    let mut os_nonce = [0u8; NONCE_LEN]; rng.fill(&mut os_nonce);
    let nonce_arr = generate_ackermann_nonce(&os_nonce);
    let nonce = Nonce::from_slice(&nonce_arr);

    let (key_enc, _) = derive_keys(password, &salt, rayo_steps)?;
    let cipher = Aes256Gcm::new_from_slice(&*key_enc).map_err(|_| CryptoError::DecryptionError)?;

    let mut plaintext = fs::read(input_path)?;
    let original_len = plaintext.len();
    if padding_level > 0 {
        let target = googol_padding_tier(password, &salt, padding_level, original_len);
        plaintext.extend((0..target - original_len).map(|_| rng.gen::<u8>()));
    }

    let mut manifest = [0u8; MANIFEST_LEN];
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let uuid = Uuid::new_v4();
    manifest[..8].copy_from_slice(&original_len.to_be_bytes());
    manifest[8..16].copy_from_slice(&ts.to_be_bytes());
    manifest[16..32].copy_from_slice(uuid.as_bytes());
    manifest[32..40].copy_from_slice(&rayo_steps.to_be_bytes());

    let mut flags = 0u8;
    if anti_replay { flags |= FLAG_ANTI_REPLAY; }
    if padding_level > 0 {
        flags |= FLAG_PADDING;
        flags |= (padding_level << 2) & PADDING_LEVEL_MASK;
    }

    let ciphertext = cipher.encrypt(nonce, Payload { msg: &plaintext, aad: &manifest })
        .map_err(|_| CryptoError::DecryptionError)?;

    let mut f = fs::File::create(&output_path)?;
    f.write_all(&[VERSION])?;
    f.write_all(&[flags])?;
    f.write_all(&salt)?;
    f.write_all(&nonce_arr)?;
    f.write_all(&manifest)?;
    f.write_all(&ciphertext)?;
    Ok(())
}

// -------------------- Decrypt --------------------
pub fn decrypt_file(input_path: &Path, output_path: &Path, password: &[u8]) -> Result<(), CryptoError> {
    let mut f = fs::File::open(input_path)?;
    let mut hdr2 = [0u8; 2]; f.read_exact(&mut hdr2)?;
    let version = hdr2[0]; let flags = hdr2[1];
    if version != VERSION { return Err(CryptoError::InvalidFormat); }

    let mut salt = [0u8; SALT_LEN]; f.read_exact(&mut salt)?;
    let mut nonce_arr = [0u8; NONCE_LEN]; f.read_exact(&mut nonce_arr)?;
    let nonce = Nonce::from_slice(&nonce_arr);

    let mut manifest = [0u8; MANIFEST_LEN]; f.read_exact(&mut manifest)?;
    let rayo_steps = u64::from_be_bytes(manifest[32..40].try_into().unwrap());

    let (key_enc, _) = derive_keys(password, &salt, rayo_steps)?;
    let cipher = Aes256Gcm::new_from_slice(&*key_enc).map_err(|_| CryptoError::DecryptionError)?;

    let mut ciphertext = Vec::new(); f.read_to_end(&mut ciphertext)?;
    let plaintext = cipher.decrypt(nonce, Payload { msg: &ciphertext, aad: &manifest })
        .map_err(|_| CryptoError::DecryptionError)?;

    let orig_len = u64::from_be_bytes(manifest[..8].try_into().unwrap()) as usize;
    if flags & FLAG_ANTI_REPLAY != 0 {
        let ts = u64::from_be_bytes(manifest[8..16].try_into().unwrap());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if now.abs_diff(ts) > 3600 { return Err(CryptoError::ReplayDetected); }
    }
    let final_plain = if flags & FLAG_PADDING != 0 {
        if orig_len > plaintext.len() { return Err(CryptoError::InvalidFormat); }
        &plaintext[..orig_len]
    } else { &plaintext };

    let mut out = fs::File::create(output_path)?;
    out.write_all(final_plain)?;
    Ok(())
}