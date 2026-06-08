use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

const STEGO_MAGIC: &[u8; 4] = b"ACYP";
const STEGO_SALT_LEN: usize = 16;

/// Прячет данные в PNG. Соль размещается в начале контейнера последовательно,
/// остальные данные — с перемешиванием на основе пароля + соль.
pub fn hide_data_in_png(png_data: &[u8], secret: &[u8], password: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let img = image::load_from_memory(png_data)?.to_rgba8();
    let (width, height) = img.dimensions();
    let total_pixels = (width as usize) * (height as usize);
    let max_bytes = total_pixels * 3 / 8;
    
    let mut salt = [0u8; STEGO_SALT_LEN];
    rand::thread_rng().fill(&mut salt);
    
    let len_bytes = (secret.len() as u32).to_be_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(STEGO_MAGIC);
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&len_bytes);
    payload.extend_from_slice(secret);
    if payload.len() > max_bytes {
        return Err("Данные слишком велики для этого изображения".into());
    }
    
    // Готовим биты всей полезной нагрузки
    let payload_bits: Vec<u8> = payload.iter().flat_map(|b| (0..8).map(move |i| (b >> (7 - i)) & 1)).collect();
    let total_bits = payload_bits.len();
    if total_bits > total_pixels * 3 {
        return Err("Недостаточно пикселей".into());
    }
    
    // Первые биты соли (STEGO_SALT_LEN * 8) размещаем последовательно в начале изображения
    let salt_bits_count = STEGO_SALT_LEN * 8;
    let mut img = img;
    for bit_idx in 0..total_bits {
        let x;
        let y;
        let channel;
        if bit_idx < salt_bits_count {
            // последовательное размещение соли
            let pixel_idx = bit_idx / 3;
            channel = bit_idx % 3;
            x = (pixel_idx as u32) % width;
            y = (pixel_idx as u32) / width;
        } else {
            // для остальных данных используем перемешанный порядок на основе пароля+соли
            let hash = {
                let mut hasher = Sha256::new();
                hasher.update(password);
                hasher.update(&salt);
                hasher.finalize()
            };
            let mut seed = [0u8; 32];
            seed[..32].copy_from_slice(&hash[..32]);
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut order: Vec<usize> = (0..total_pixels).collect();
            for i in (1..order.len()).rev() {
                let j = (rng.gen::<u64>() as usize) % (i + 1);
                order.swap(i, j);
            }
            // индекс бита для перемешанного размещения
            let shuffled_bit_idx = bit_idx - salt_bits_count;
            let pixel_idx = order[shuffled_bit_idx / 3];
            channel = shuffled_bit_idx % 3;
            x = (pixel_idx as u32) % width;
            y = (pixel_idx as u32) / width;
        }
        let mut pixel = *img.get_pixel(x, y);
        pixel[channel] = (pixel[channel] & 0xFE) | payload_bits[bit_idx];
        img.put_pixel(x, y, pixel);
    }
    
    let mut output = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut output), image::ImageFormat::Png)?;
    Ok(output)
}

/// Извлекает данные: сначала читает соль из фиксированного места, затем остальное.
pub fn extract_data_from_png(png_data: &[u8], password: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let img = image::load_from_memory(png_data)?.to_rgba8();
    let (width, height) = img.dimensions();
    let total_pixels = (width as usize) * (height as usize);
    
    // Читаем первые биты (соль) последовательно
    let salt_bits_count = STEGO_SALT_LEN * 8;
    let mut salt_bits = Vec::new();
    for bit_idx in 0..salt_bits_count {
        let pixel_idx = bit_idx / 3;
        let channel = bit_idx % 3;
        let x = (pixel_idx as u32) % width;
        let y = (pixel_idx as u32) / width;
        salt_bits.push(img.get_pixel(x, y)[channel] & 1);
    }
    let salt_bytes: Vec<u8> = salt_bits.chunks(8).map(|c| c.iter().fold(0u8, |acc, b| (acc << 1) | b)).collect();
    if salt_bytes.len() < STEGO_SALT_LEN { return Err("Нет соли".into()); }
    let salt = &salt_bytes[..STEGO_SALT_LEN];
    
    // Генерируем порядок для остальных данных
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        hasher.finalize()
    };
    let mut seed = [0u8; 32];
    seed[..32].copy_from_slice(&hash[..32]);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut order: Vec<usize> = (0..total_pixels).collect();
    for i in (1..order.len()).rev() {
        let j = (rng.gen::<u64>() as usize) % (i + 1);
        order.swap(i, j);
    }
    
    // Читаем оставшиеся биты
    let mut bits = Vec::with_capacity(total_pixels * 3 - salt_bits_count);
    // сначала копируем соль
    bits.extend_from_slice(&salt_bits);
    // затем из перемешанных пикселей
    for shuffled_bit_idx in 0..(total_pixels * 3 - salt_bits_count) {
        let pixel_idx = order[shuffled_bit_idx / 3];
        let channel = shuffled_bit_idx % 3;
        let x = (pixel_idx as u32) % width;
        let y = (pixel_idx as u32) / width;
        bits.push(img.get_pixel(x, y)[channel] & 1);
    }
    
    let bytes: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |acc, b| (acc << 1) | b)).collect();
    if bytes.len() < 4 + STEGO_SALT_LEN + 4 { return Err("Нет данных".into()); }
    if &bytes[..4] != STEGO_MAGIC { return Err("Неверный пароль или повреждённый контейнер".into()); }
    // соль уже в bytes[4..4+STEGO_SALT_LEN], но мы её уже прочитали, пропускаем
    let len = u32::from_be_bytes(bytes[4+STEGO_SALT_LEN..4+STEGO_SALT_LEN+4].try_into().unwrap()) as usize;
    if bytes.len() < 4 + STEGO_SALT_LEN + 4 + len { return Err("Повреждённые данные".into()); }
    Ok(bytes[4+STEGO_SALT_LEN+4..4+STEGO_SALT_LEN+4+len].to_vec())
}