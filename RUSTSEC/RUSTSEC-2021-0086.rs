// https://github.com/sunrise-choir/flumedb-rs/issues/10

const N: usize = 255;

unsafe fn before() {
    let mut buf: Vec<u8> = Vec::with_capacity(N);
    unsafe { buf.set_len(N) };
}

fn after() {
    let mut buf: Vec<u8> = vec![0; N];
}
