use criterion::{criterion_group, criterion_main, Criterion};

fn encrypt_bench(c: &mut Criterion) {
    let key = aes_crypt::gen_key();
    let plain_text = "This is a test message".as_bytes().to_vec();
    
    c.bench_function(
        "encrypt",
        |b| b.iter(|| aes_crypt::encrypt(&plain_text, &key))
    );
}

criterion_group!(
    benches,
    encrypt_bench
);

criterion_main!(benches);