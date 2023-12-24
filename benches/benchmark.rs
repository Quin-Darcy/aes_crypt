use aes_crypt::*;
use criterion::{criterion_group, criterion_main, Criterion};

fn encrypt_bench(c: &mut Criterion) {
    let key_path: &str = "/home/arbegla/projects/rust/libraries/aes_crypt/key.txt";
    let src_file_path: &str = "/home/arbegla/pictures/backgrounds/background1.jpg";
    let dst_file_path: &str = "/home/arbegla/projects/rust/libraries/aes_crypt/enc.txt";
    
    gen_key(key_path);
    c.bench_function(
        "encrypt",
        |b| b.iter(|| aes_crypt::encrypt(src_file_path, dst_file_path, key_path))
    );
}

criterion_group!(
    benches,
    encrypt_bench
);

criterion_main!(benches);
