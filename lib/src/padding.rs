#[derive(Debug, PartialEq)]
pub enum PaddingError {
    BadPadding
}

pub fn pkcs7(input: &[u8], size: usize) -> Vec<u8> {
    let input_size = input.len();
    let diff = size - input_size;

    let mut result = Vec::with_capacity(size);
    result.extend_from_slice(input);
    result.append(&mut vec![diff as u8; diff]);
    result
}

pub fn remove_pkcs7(input: &[u8]) -> Result<Vec<u8>, PaddingError>  {
    if input.is_empty() {
        return Ok(input.to_vec());
    }

    let last_byte = input[input.len() - 1];
    if last_byte <= 0 || last_byte > 16 {
        return Err(PaddingError::BadPadding);
    } 

    if input[input.len() - last_byte as usize..].iter().all(|&b| b == last_byte) {
        return Ok(input[..input.len() - last_byte as usize].to_vec())
    }

    Err(PaddingError::BadPadding)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_pkcs7() {
        let padded = pkcs7("YELLOW SUBMARINE".as_bytes(), 20);
        assert_eq!(padded, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
    }

    #[test]
    fn test_pkcs7_valid() {
        assert_eq!(remove_pkcs7("ICE ICE BABY\x04\x04\x04\x04".as_bytes()).unwrap(), "ICE ICE BABY".as_bytes());
    }

    #[test]
    fn test_pkcs7_invalid() {
        assert_eq!(remove_pkcs7("ICE ICE BABY\x01\x02\x03\x04".as_bytes()).err().unwrap(), PaddingError::BadPadding);
    }
}
