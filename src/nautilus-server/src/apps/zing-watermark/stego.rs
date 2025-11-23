//! LSB Steganography utilities for PNG images
//! Embeds and extracts text data in the least significant bits of image pixels

use anyhow::{Context, Result};
use std::io::Cursor;

const MAGIC_HEADER: &str = "ZING_STEGO";
const VERSION: u32 = 1;

/// Convert string to binary representation (UTF-8 aware)
fn string_to_binary(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

/// Convert binary bytes to string (UTF-8 aware)
fn binary_to_string(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .context("Failed to decode UTF-8 string from binary data")
}

/// Convert bytes to binary string representation (for header parsing)
fn bytes_to_binary_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:08b}", byte))
        .collect::<String>()
}

/// Convert binary string to bytes
fn binary_string_to_bytes(binary: &str) -> Vec<u8> {
    binary
        .as_bytes()
        .chunks(8)
        .map(|chunk| {
            let byte_str = std::str::from_utf8(chunk).unwrap_or("00000000");
            u8::from_str_radix(byte_str, 2).unwrap_or(0)
        })
        .collect()
}

/// Create a header with magic string, version, and message byte length
fn create_header(message_byte_length: usize) -> Vec<u8> {
    let header = format!("{}|v{}|len:{}|", MAGIC_HEADER, VERSION, message_byte_length);
    string_to_binary(&header)
}

/// Parse header to extract message length
fn parse_header(binary_data: &[u8]) -> Result<(usize, usize)> {
    // Try to read first 200 bits (25 bytes, should be enough for header)
    let header_bytes = binary_data.get(0..200.min(binary_data.len())).unwrap_or(&[]);
    let header_binary = bytes_to_binary_string(header_bytes);
    
    // Convert binary string to bytes for UTF-8 decoding
    let header_bytes_decoded = binary_string_to_bytes(&header_binary);
    let header_text = binary_to_string(&header_bytes_decoded)?;

    // Parse header using regex
    let re = regex::Regex::new(r"ZING_STEGO\|v(\d+)\|len:(\d+)\|")
        .context("Failed to create regex pattern")?;
    
    let caps = re
        .captures(&header_text)
        .ok_or_else(|| anyhow::anyhow!("No valid steganography header found"))?;

    let version: u32 = caps
        .get(1)
        .and_then(|m| m.as_str().parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Failed to parse version"))?;

    if version != VERSION {
        return Err(anyhow::anyhow!("Unsupported version: {}", version));
    }

    let message_length: usize = caps
        .get(2)
        .and_then(|m| m.as_str().parse().ok())
        .ok_or_else(|| anyhow::anyhow!("Failed to parse message length"))?;

    let header_string = caps.get(0).unwrap().as_str();
    let header_length = string_to_binary(header_string).len() * 8; // Convert to bits

    Ok((header_length, message_length))
}

/// Embed text message into PNG image buffer using LSB steganography
pub fn embed_message(image_buffer: &[u8], message: &str) -> Result<Vec<u8>> {
    let decoder = png::Decoder::new(Cursor::new(image_buffer));
    let mut reader = decoder.read_info()?;
    
    // Get info before reading frame to avoid borrow conflicts
    let width = reader.info().width as usize;
    let height = reader.info().height as usize;
    let color_type = reader.info().color_type;
    let bit_depth = reader.info().bit_depth;
    let bytes_per_pixel = reader.info().bytes_per_pixel();
    let palette = reader.info().palette.clone();
    let trns = reader.info().trns.clone();
    
    // Read image data
    let mut buf = vec![0u8; reader.output_buffer_size()];
    reader.next_frame(&mut buf)?;
    
    // Create header and message binary (use byte length for UTF-8 strings)
    let message_bytes = message.as_bytes();
    let message_byte_length = message_bytes.len();
    let header = create_header(message_byte_length);
    let message_binary = string_to_binary(message);
    let full_binary = [header.as_slice(), message_binary.as_slice()].concat();
    
    // Convert bytes to binary bits (each byte becomes 8 bits)
    let mut full_bits = Vec::new();
    for byte in &full_binary {
        for i in 0..8 {
            full_bits.push((byte >> (7 - i)) & 1);
        }
    }
    
    // Check capacity (1 bit per color channel, 3 channels per pixel for RGB/RGBA, skipping alpha)
    // For PNG, we need to handle different color types
    let channels_per_pixel = match color_type {
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 3, // Skip alpha channel
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 1, // Skip alpha channel
        png::ColorType::Indexed => {
            return Err(anyhow::anyhow!("Indexed color type not supported for steganography"));
        }
    };
    
    let capacity = width * height * channels_per_pixel;
    if full_bits.len() > capacity {
        return Err(anyhow::anyhow!(
            "Message too long. Max capacity: {} bytes, message: {} bytes",
            capacity / 8,
            full_bits.len() / 8
        ));
    }
    
    // Embed binary data into LSBs
    // First, collect all modifications to avoid borrow conflicts
    let mut modifications = Vec::new();
    let mut bit_index = 0;
    
    for (pixel_idx, chunk) in buf.chunks_exact(bytes_per_pixel).enumerate() {
        for (channel_idx, &pixel_value) in chunk.iter().enumerate() {
            // Skip alpha channel (last channel in RGBA/GrayscaleAlpha)
            let is_alpha = match color_type {
                png::ColorType::Rgba => channel_idx == 3,
                png::ColorType::GrayscaleAlpha => channel_idx == 1,
                _ => false,
            };
            
            if is_alpha {
                continue;
            }
            
            if bit_index < full_bits.len() {
                // Clear LSB and set new bit
                let bit = full_bits[bit_index];
                let pixel_offset = pixel_idx * bytes_per_pixel + channel_idx;
                modifications.push((pixel_offset, (pixel_value & 0xFE) | bit));
                bit_index += 1;
            }
        }
    }
    
    // Apply modifications
    for (offset, new_value) in modifications {
        buf[offset] = new_value;
    }
    
    // Encode back to PNG
    let mut output = Vec::new();
    {
        let mut encoder = png::Encoder::new(Cursor::new(&mut output), width as u32, height as u32);
        encoder.set_color(color_type);
        encoder.set_depth(bit_depth);
        if let Some(pal) = palette.as_ref() {
            encoder.set_palette(pal.clone());
        }
        if let Some(trns_data) = trns.as_ref() {
            encoder.set_trns(trns_data.clone());
        }
        
        let mut writer = encoder.write_header()?;
        writer.write_image_data(&buf)?;
    }
    
    Ok(output)
}

/// Extract embedded message from PNG image buffer
pub fn extract_message(image_buffer: &[u8]) -> Result<String> {
    let decoder = png::Decoder::new(Cursor::new(image_buffer));
    let mut reader = decoder.read_info()?;
    let bytes_per_pixel = reader.info().bytes_per_pixel();
    let color_type = reader.info().color_type;
    
    // Read image data
    let mut buf = vec![0u8; reader.output_buffer_size()];
    reader.next_frame(&mut buf)?;
    
    // Extract bits from LSBs
    let mut binary_bits = Vec::new();
    
    for chunk in buf.chunks_exact(bytes_per_pixel) {
        for (channel_idx, &pixel_value) in chunk.iter().enumerate() {
            // Skip alpha channel
            let is_alpha = match color_type {
                png::ColorType::Rgba => channel_idx == 3,
                png::ColorType::GrayscaleAlpha => channel_idx == 1,
                _ => false,
            };
            
            if is_alpha {
                continue;
            }
            
            binary_bits.push(pixel_value & 1);
        }
    }
    
    // Convert bits to bytes (8 bits per byte)
    let mut binary_bytes = Vec::new();
    for chunk in binary_bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if chunk.len() == 8 {
                byte |= (bit as u8) << (7 - i);
            }
        }
        if chunk.len() == 8 {
            binary_bytes.push(byte);
        }
    }
    
    // Parse header
    let (header_length_bits, message_length) = parse_header(&binary_bytes)?;
    let header_length_bytes = header_length_bits / 8;
    
    // Extract message bits
    let message_start_byte = header_length_bytes;
    let message_end_byte = message_start_byte + message_length;
    
    if message_end_byte > binary_bytes.len() {
        return Err(anyhow::anyhow!(
            "Message length exceeds available data. Expected {} bytes, but only {} bytes available",
            message_length,
            binary_bytes.len() - message_start_byte
        ));
    }
    
    let message_bytes = &binary_bytes[message_start_byte..message_end_byte];
    binary_to_string(message_bytes)
}

/// Validate if buffer is a valid PNG
pub fn is_valid_png(buffer: &[u8]) -> bool {
    // Check PNG signature: 89 50 4E 47 0D 0A 1A 0A
    if buffer.len() < 8 {
        return false;
    }
    
    let signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if buffer[0..8] != signature {
        return false;
    }
    
    // Try to decode to verify it's a valid PNG
    let decoder = png::Decoder::new(Cursor::new(buffer));
    decoder.read_info().is_ok()
}

/// Get maximum message capacity for a PNG image
pub fn get_capacity(image_buffer: &[u8]) -> Result<usize> {
    let decoder = png::Decoder::new(Cursor::new(image_buffer));
    let reader = decoder.read_info()?;
    let info = reader.info();
    
    let width = info.width as usize;
    let height = info.height as usize;
    let color_type = info.color_type;
    
    // Calculate available bits
    let channels_per_pixel = match color_type {
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 3, // Skip alpha channel
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 1, // Skip alpha channel
        png::ColorType::Indexed => {
            return Err(anyhow::anyhow!("Indexed color type not supported for steganography"));
        }
    };
    
    let bits_available = width * height * channels_per_pixel;
    
    // Account for header overhead (approx 25 bytes = 200 bits)
    let header_overhead = 25 * 8;
    Ok((bits_available.saturating_sub(header_overhead)) / 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_string_to_binary() {
        let result = string_to_binary("test");
        assert_eq!(result, b"test");
    }
    
    #[test]
    fn test_binary_to_string() {
        let result = binary_to_string(b"test").unwrap();
        assert_eq!(result, "test");
    }
    
    #[test]
    fn test_create_header() {
        let header = create_header(100);
        let header_str = binary_to_string(&header).unwrap();
        assert!(header_str.contains("ZING_STEGO"));
        assert!(header_str.contains("len:100"));
    }
    
    #[test]
    fn test_parse_header() {
        let header = create_header(100);
        let header_bits: Vec<u8> = header.iter().flat_map(|&b| {
            (0..8).map(move |i| (b >> (7 - i)) & 1)
        }).collect();
        
        // Convert bits back to bytes for parsing
        let mut header_bytes = Vec::new();
        for chunk in header_bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &bit) in chunk.iter().enumerate() {
                if chunk.len() == 8 {
                    byte |= (bit as u8) << (7 - i);
                }
            }
            if chunk.len() == 8 {
                header_bytes.push(byte);
            }
        }
        
        let (_, message_length) = parse_header(&header_bytes).unwrap();
        assert_eq!(message_length, 100);
    }
}

