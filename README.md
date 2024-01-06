# aes_crypt
This library offers 3 simple public functions:
 
1. `aes_crypt::encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8>`: This function takes two arguments. In practice, the arguments passed in are typically `&Vec<u8>`. This function takes the plaintext bytes and the key bytes then encrypts the plaintext with the given key. The return value is a vector of encrypted bytes. 

2. `aes_crypt::decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8>`: This function takes 2 arguments. Similar to the `encrypt` method, in practice, `&Vec<u8>` is usually the data type of the arguemnts passed in. The function returns a vector of decrypted bytes.  

3. `aes_crypt::gen_key() -> Vec<u8>`: This function takes no arguments and returns a vector of bytes. The number of bytes it returns is equal to `4 * Nk`, where `Nk` determines the key length and is defined in `src/constants.rs`. Note that this function uses the `rand` library to generate random bytes and this library may or may not be compliant with NIST SP 800-90A. This means the function itself may or may not be compliant with NIST SP 800-133. This function shall only be used in applications where full compliance is not required and simple key generation is sufficient. 

### Example
```
use aes_crypt;


fn main() {
    // Generate the key
    let key: Vec<u8> = aes_crypt::gen_key();

    // Initialize the message to be encrypted
    let message: &str = "This is a message."
    let message_bytes: Vec<u8> = message.as_bytes().to_vec();

    // Get the encrypted message
    let encrypted_bytes: Vec<u8> = aes_crypt::encrypt(&message_bytes, &key);

    // Get the decrypted bytes
    let decrypted_bytes: Vec<u8> = aes_crypt::decrypt(&encrypted_bytes, &key);

    // Display the encrypted message
    let encrypted_message: String = String::from_utf8_lossy(&encrypted_bytes);
    println!("Encrypted Message: {}", encrypted_message);

    // Display the decrypted message
    let decrypted_message: String = String::from_utf8_lossy(&decrypted_bytes);
    println!("Decrypted Message: {}", decrypted_message);
}
```
