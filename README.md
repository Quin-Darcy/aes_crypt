# aes_crypt
This library offers 3 simple public functions:
1. `aes_crypt::gen_key(key_file_path: &str)`: This function takes a file path as its only argument and generates an (`32 * Nk`)-bit key, creates a file at the location specified by `key_path`, and writes the key to the file.
2. `aes_crypt::encrypt(src_file_path: &str, dst_file_path: &str, key_file_path: &str)`: This function takes 3 arguments - The path to the file which is to be encrypted, the path to the new file location to store the encrypted bytes, and the path to the file containing the encryption key.
3. `aes_crypt::decrypt(src_file_path: &str, dst_file_path: &str, key_file_path: &str)`: This function takes 3 arguments - The path to the file which is to be decrypted, the path to the new file location to store the decrypted bytes, and the path to the file contianing the decryption key.  
