const CHUNK_SIZE: usize = 8;
use useful_macro::*;

pub fn encrypt(payload: &[u8], key: &[u8]) -> Vec<u8> {
    let encrypted = idea_crypto::encrypt(payload, key);

    let mut result = Vec::with_capacity(encrypted.len() * CHUNK_SIZE);

    for chunk in encrypted {
        result.extend(chunk);
    }

    return result;
}

pub fn decrypt(payload: &[u8], key: &[u8]) -> Vec<u8> {
    let mut enc = payload
        .chunks(8)
        .into_iter()
        .map(|s| s.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let count_push: u8 = vec_element_clone!(&enc[enc.len() - 1], &enc[enc.len() - 1].len() - 1);

    enc.remove(enc.len() - 1);
    let mut last = vec_element_clone!(enc, enc.len() - 1);
    last.push(count_push);
    enc.remove(enc.len() - 1);
    enc.push(last);

    let decrypted = idea_crypto::decrypt(enc, key);

    let mut size = 0;

    for item in &decrypted {
        size += item.len()
    }

    let mut result = Vec::with_capacity(size);

    for item in decrypted {
        result.extend(item)
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

        let decrypted = decrypt(&encrypted, "Key".as_bytes());

        assert_eq!(&src, &decrypted);
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
