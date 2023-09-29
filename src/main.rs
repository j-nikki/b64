#![feature(stdsimd)]
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::mem::size_of;
use std::{io, ops::Mul};

fn print_bits<T: std::fmt::Binary>(x: T) {
    let mut buf = [0u8; 64];
    unsafe {
        std::ptr::write_unaligned(buf.as_mut_ptr() as *mut T, x);
    }
    for (i, b) in buf.iter().take(size_of::<T>()).rev().enumerate() {
        if i != 0 {
            print!("'");
        }
        print!("{:08b}", b);
    }
    println!();
}

fn print_bytes(x: __m512i) {
    let mut buf = [0u8; 64];
    unsafe {
        _mm512_storeu_epi8(buf.as_mut_ptr() as *mut i8, x);
    }
    for (i, c) in buf.iter().rev().enumerate() {
        if i != 0 && i % 4 == 0 {
            print!("'");
        }
        print!("{:02x}", c);
    }
    println!();
}

unsafe fn loadu<T>(src: *const i8) -> T {
    let src = src as *const T;
    std::ptr::read_unaligned(src)
}

unsafe fn storeu<T>(src: T, dst: *mut i8) {
    let dst = dst as *mut T;
    std::ptr::write_unaligned(dst, src);
}

trait AsI64 {
    fn cast(self) -> i64;
}
impl AsI64 for i64 {
    fn cast(self) -> i64 {
        self
    }
}
impl AsI64 for char {
    fn cast(self) -> i64 {
        self as i64
    }
}

unsafe fn vec<T: AsI64 + Copy>(chars: &[T; 8]) -> __m512i {
    _mm512_set_epi64(
        (chars[7].cast() * 0x1010101_01010101i64) as i64,
        (chars[6].cast() * 0x1010101_01010101i64) as i64,
        (chars[5].cast() * 0x1010101_01010101i64) as i64,
        (chars[4].cast() * 0x1010101_01010101i64) as i64,
        (chars[3].cast() * 0x1010101_01010101i64) as i64,
        (chars[2].cast() * 0x1010101_01010101i64) as i64,
        (chars[1].cast() * 0x1010101_01010101i64) as i64,
        (chars[0].cast() * 0x1010101_01010101i64) as i64,
    )
}

unsafe fn setr_epi8(chars: &[u8; 64]) -> __m512i {
    let src = chars.as_ptr() as *const __m512i;
    std::ptr::read_unaligned(src)
}

#[cfg(debug_assertions)]
macro_rules! debug_only {
    ($($x:tt)*) => { $($x)* }
}

unsafe fn b64_decode_impl(mut f: *const i8, l: *const i8, mut dit: *mut i8) {
    while f != l {
        debug_only!(println!("-----"));
        let xs = _mm512_set1_epi64(loadu(f));
        debug_only!(print!("xs: "); print_bytes(xs));

        let sub = _mm512_sub_epi8(xs, vec(&['A', 'a', '0', '+', '/', '-', '_', '=']));
        debug_only!(print!("sub: "); print_bytes(sub));

        let lt = _mm512_cmplt_epu8_mask(sub, vec(&[26, 26, 10, 1, 1, 1, 1, 1]));
        debug_only!(print!("lt: "); print_bits(lt));

        let add = _mm512_maskz_add_epi8(lt, sub, vec(&[0, 26, 52, 62, 63, 62, 63, 0]));
        debug_only!(print!("add: "); print_bytes(add));
        let or_ = _mm512_reduce_or_epi64(add);
        debug_only!(print!("or_: "); print_bits(or_));

        let bc = _mm512_set1_epi64(or_);
        let bs = _mm512_bitshuffle_epi64_mask(
            bc,
            setr_epi8(&[
                0o14, 0o15, 0o00, 0o01, 0o02, 0o03, 0o04, 0o05, //
                0o22, 0o23, 0o24, 0o25, 0o10, 0o11, 0o12, 0o13, //
                0o30, 0o31, 0o32, 0o33, 0o34, 0o35, 0o20, 0o21, //
                0o54, 0o55, 0o40, 0o41, 0o42, 0o43, 0o44, 0o45, //
                0o62, 0o63, 0o64, 0o65, 0o50, 0o51, 0o52, 0o53, //
                0o70, 0o71, 0o72, 0o73, 0o74, 0o75, 0o60, 0o61, //
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
        );
        debug_only!(print!("bs: "); print_bits(bs));

        storeu(bs, dit);
        dit = dit.add(6);
        f = f.add(8);
    }
}

fn b64_decode(in_: &[u8], out: &mut [u8]) -> usize {
    debug_assert!(in_.len() % 8 == 0, "input buffer must be divisible by 8");
    let n = (in_.len() + 7) / 8;
    debug_assert!(
        out.len() >= n * 6 + 2,
        "output buffer must be sufficiently large"
    );
    unsafe {
        b64_decode_impl(
            in_.as_ptr() as *const i8,
            in_.as_ptr().add(n * 8) as *const i8,
            out.as_mut_ptr() as *mut i8,
        );
    }
    in_.len() / 4 * 3
}

fn b64_decode_prune(in_: &[u8], out: &mut [u8]) -> usize {
    debug_assert!(in_.len() % 8 == 0, "input buffer must be divisible by 8");
    let nin = in_.len();
    let pad = if nin == 0 {
        0
    } else if in_[nin - 2] == b'=' {
        2
    } else if in_[nin - 1] == b'=' {
        1
    } else {
        0
    };
    b64_decode(in_, out) - pad
}

fn main() -> io::Result<()> {
    let mut ibuf = String::new();
    io::stdin().read_line(&mut ibuf)?;
    let ibuf: Vec<u8> = {
        let nibuf = ibuf.as_bytes().len();
        if nibuf % 8 == 0 {
            ibuf.into_bytes()
        } else {
            ibuf.into_bytes()
                .into_iter()
                .chain(std::iter::repeat(0).take(8 - (nibuf % 8)))
                .collect()
        }
    };
    let ocap = (ibuf.len() + 7) / 8 * 6 + 2;
    let mut obuf = vec![0; ocap];
    let nobuf = b64_decode_prune(&ibuf, &mut obuf);
    unsafe {
        println!(
            "{}",
            String::from_utf8_unchecked(obuf.into_iter().take(nobuf).collect())
        );
    }
    Ok(())
}
