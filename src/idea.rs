pub fn encrypt(payload: &[u8], key: &[u8]) -> Vec<u8> {
    let encrypted = if payload.len() != 8 {
        idea_crypto::encrypt(payload, key)
    } else {
        let mut new_payload = Vec::with_capacity(payload.len() + 1);
        new_payload.extend_from_slice(payload);
        new_payload.push(0);
        idea_crypto::encrypt(new_payload.as_slice(), key)
    };

    let mut result = Vec::new();
    for chunk in encrypted {
        result.push(chunk.len() as u8);
        result.extend(chunk);
    }

    return result;
}

pub fn decrypt(data: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let mut to_decrypt = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let size = data[i] as usize;
        i += 1;

        to_decrypt.push(data[i..(i + size)].to_vec());
        i += size;
    }

    let decrypted = idea_crypto::decrypt(to_decrypt, key);

    let mut result = Vec::new();

    for chunk in decrypted {
        result.extend(chunk)
    }

    if result.len() == 9 && result[result.len() - 1] == 0u8 {
        result.pop();
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let src = vec![1u8, 2u8, 3u8, 4u8];
        let encrypted = encrypt(&src, "Key".as_bytes());

        let decrypted = decrypt(encrypted, "Key".as_bytes());

        assert_eq!(&src, &decrypted);
    }

    #[test]
    fn test_8() {
        let src = "01234567";
        let key = "1234567890123456";
        let encrypted = encrypt(src.as_bytes(), key.as_bytes());

        let decrypted = decrypt(encrypted, key.as_bytes());

        assert_eq!(src, std::str::from_utf8(&decrypted).unwrap());
    }

    #[test]
    fn test_that_two_encryptions_are_the_same() {
        for b in 0u8..255 {
            let src = vec![b, b, b, b];
            let encrypted1 = encrypt(&src, "Key".as_bytes());
            let encrypted2 = encrypt(&src, "Key".as_bytes());

            assert_eq!(encrypted1, encrypted2);
        }
    }
}
