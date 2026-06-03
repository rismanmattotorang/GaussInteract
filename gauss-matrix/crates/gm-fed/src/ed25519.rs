// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 signatures (RFC 8032) and SHA-512 (FIPS 180-4), pure-`std`.
//!
//! Federation request and key-document signing uses Ed25519 (spec §III.E): a
//! server holds a 32-byte secret seed and publishes the 32-byte public key it
//! derives; verifiers hold only the public key. This module is a dependency-free
//! implementation of the primitive — SHA-512, the field arithmetic over the
//! prime `2^255 − 19`, the Edwards25519 group, and the sign/verify procedures —
//! exercised against the RFC 8032 §7.1 test vectors.
//!
//! Keys and signatures cross the wire as **unpadded base64** (Matrix's
//! encoding), so the public helpers ([`sign_b64`], [`verify_b64`],
//! [`public_key_b64`]) take and return base64 strings.

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4)
// ---------------------------------------------------------------------------

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-512 of `msg`, returning the 64-byte digest.
pub fn sha512(msg: &[u8]) -> [u8; 64] {
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    // Pad: message || 0x80 || 0x00… || 128-bit big-endian bit length.
    let bit_len = (msg.len() as u128) * 8;
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 128 != 112 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u64; 80];
    for block in data.chunks_exact(128) {
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *word = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (hi, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *hi = hi.wrapping_add(v);
        }
    }

    let mut out = [0u8; 64];
    for (i, word) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Field arithmetic mod p = 2^255 - 19, elements as 4 little-endian 64-bit limbs.
// ---------------------------------------------------------------------------

/// A field element mod `p = 2^255 − 19`, four little-endian 64-bit limbs.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Fe([u64; 4]);

const P: [u64; 4] = [
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
];

impl Fe {
    const ZERO: Fe = Fe([0, 0, 0, 0]);
    const ONE: Fe = Fe([1, 0, 0, 0]);

    fn from_u64(n: u64) -> Fe {
        Fe([n, 0, 0, 0])
    }

    /// Reduce `self` fully into `[0, p)` (it is always `< 2p` on entry).
    fn canonical(self) -> Fe {
        // Conditionally subtract p once.
        let (r, borrow) = sub_limbs(self.0, P);
        if borrow == 0 {
            Fe(r)
        } else {
            self
        }
    }

    fn add(self, other: Fe) -> Fe {
        let (mut r, carry) = add_limbs(self.0, other.0);
        // Sum < 2*(2^255) so the top bit may carry into a 256th bit; fold 2^256≡38.
        if carry != 0 {
            r = add_small(r, 38);
        }
        Fe(r).canonical()
    }

    fn sub(self, other: Fe) -> Fe {
        let (mut r, borrow) = sub_limbs(self.0, other.0);
        if borrow != 0 {
            // Add p back.
            let (r2, _) = add_limbs(r, P);
            r = r2;
        }
        Fe(r)
    }

    fn mul(self, other: Fe) -> Fe {
        let wide = mul_wide(self.0, other.0); // 8 limbs
        Fe(reduce_512(wide)).canonical()
    }

    fn sq(self) -> Fe {
        self.mul(self)
    }

    /// `self^(p-2) mod p` — the multiplicative inverse (Fermat).
    fn invert(self) -> Fe {
        // p - 2 = 2^255 - 21. Exponentiate by squaring over its bits.
        let exp = [
            0xffffffffffffffeb,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x7fffffffffffffff,
        ];
        self.pow(exp)
    }

    fn pow(self, exp: [u64; 4]) -> Fe {
        let mut result = Fe::ONE;
        for i in (0..4).rev() {
            for bit in (0..64).rev() {
                result = result.sq();
                if (exp[i] >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    fn is_negative(self) -> bool {
        self.canonical().0[0] & 1 == 1
    }

    fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn to_bytes(self) -> [u8; 32] {
        let c = self.canonical();
        let mut out = [0u8; 32];
        for (i, limb) in c.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    fn from_bytes(b: &[u8; 32]) -> Fe {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&b[i * 8..i * 8 + 8]);
            *limb = u64::from_le_bytes(buf);
        }
        limbs[3] &= 0x7fffffffffffffff; // mask the sign bit; value already < 2^255
        Fe(limbs)
    }
}

fn add_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + carry;
        r[i] = s as u64;
        carry = s >> 64;
    }
    (r, carry as u64)
}

fn add_small(a: [u64; 4], n: u64) -> [u64; 4] {
    let (r, _) = add_limbs(a, [n, 0, 0, 0]);
    r
}

fn sub_limbs(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], u64) {
    let mut r = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let d = a[i] as i128 - b[i] as i128 - borrow;
        if d < 0 {
            r[i] = (d + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            r[i] = d as u64;
            borrow = 0;
        }
    }
    (r, borrow as u64)
}

/// Schoolbook 4×4-limb product → 8 limbs (512 bits), with carries propagated
/// per term so no `u128` accumulator overflows.
fn mul_wide(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let cur = out[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
            out[i + j] = cur as u64;
            carry = cur >> 64;
        }
        // Propagate the remaining carry through the higher limbs.
        let mut k = i + 4;
        while carry != 0 {
            let cur = out[k] as u128 + carry;
            out[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
    out
}

/// Reduce a 512-bit value mod p, folding the high half via 2^256 ≡ 38 (since
/// 2^255 ≡ 19) until only a 256-bit value remains, then subtracting p.
fn reduce_512(w: [u64; 8]) -> [u64; 4] {
    let mut lo = [w[0], w[1], w[2], w[3]];
    let mut hi = [w[4], w[5], w[6], w[7]];
    loop {
        // acc = lo + 38*hi; `over` is the (small) part beyond 2^256.
        let (acc, over) = mul38_add(hi, lo);
        lo = acc;
        if over == 0 {
            break;
        }
        hi = [over, 0, 0, 0];
    }
    // lo < 2^256 ≈ 2p; subtract p at most twice to land in [0, p).
    lo = cond_sub_p(lo);
    cond_sub_p(lo)
}

/// `base + 38*hi`, returning the low 256 bits and the (small, <2^64) overflow.
fn mul38_add(hi: [u64; 4], base: [u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let cur = base[i] as u128 + hi[i] as u128 * 38u128 + carry;
        out[i] = cur as u64;
        carry = cur >> 64;
    }
    (out, carry as u64)
}

/// Subtract p from `v` if `v >= p`, else return `v` unchanged.
fn cond_sub_p(v: [u64; 4]) -> [u64; 4] {
    if less_than(v, P) {
        v
    } else {
        sub_limbs(v, P).0
    }
}

// ---------------------------------------------------------------------------
// Edwards25519 group (twisted Edwards, a = -1), extended coordinates (X,Y,Z,T).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

fn d_const() -> Fe {
    // d = -121665 / 121666 mod p
    let num = Fe::from_u64(121665).neg();
    let den = Fe::from_u64(121666);
    num.mul(den.invert())
}

impl Point {
    fn identity() -> Point {
        Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    fn base() -> Point {
        // y = 4/5; x recovered with the even/positive sign per RFC 8032.
        let y = Fe::from_u64(4).mul(Fe::from_u64(5).invert());
        decode(&encode_y(y, false)).expect("base point decodes")
    }

    fn add(&self, o: &Point) -> Point {
        // Twisted Edwards extended addition (a = -1), RFC 8032 / Hisil et al.
        let a = self.x.sub(self.y).mul(o.x.sub(o.y));
        let b = self.x.add(self.y).mul(o.x.add(o.y));
        let c = self.t.mul(o.t).mul(d_const()).mul(Fe::from_u64(2));
        let dd = self.z.mul(o.z).mul(Fe::from_u64(2));
        let e = b.sub(a);
        let f = dd.sub(c);
        let g = dd.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    fn double(&self) -> Point {
        self.add(self)
    }

    fn scalar_mul(&self, scalar: &[u8; 32]) -> Point {
        // Double-and-add over the 256 bits of the scalar, MSB first.
        let mut r = Point::identity();
        for i in (0..256).rev() {
            r = r.double();
            let byte = scalar[i / 8];
            if (byte >> (i % 8)) & 1 == 1 {
                r = r.add(self);
            }
        }
        r
    }

    /// Affine `(x, y)` via a single inversion of `z`.
    fn to_affine(self) -> (Fe, Fe) {
        let zinv = self.z.invert();
        (self.x.mul(zinv), self.y.mul(zinv))
    }

    fn encode(&self) -> [u8; 32] {
        let (x, y) = self.to_affine();
        encode_y(y, x.is_negative())
    }
}

/// Encode a point from its affine `y` and the sign of `x`.
fn encode_y(y: Fe, x_negative: bool) -> [u8; 32] {
    let mut out = y.to_bytes();
    if x_negative {
        out[31] |= 0x80;
    }
    out
}

/// Decode a 32-byte compressed point, or `None` if it is not on the curve.
fn decode(b: &[u8; 32]) -> Option<Point> {
    let sign = (b[31] >> 7) & 1 == 1;
    let y = Fe::from_bytes(b);

    // x^2 = (y^2 - 1) / (d*y^2 + 1)
    let y2 = y.sq();
    let num = y2.sub(Fe::ONE);
    let den = d_const().mul(y2).add(Fe::ONE);
    let mut x = sqrt_ratio(num, den)?;

    if x.is_negative() != sign {
        x = x.neg();
    }
    // Reject the non-canonical x = 0 with sign set.
    if x == Fe::ZERO && sign {
        return None;
    }
    let t = x.mul(y);
    Some(Point {
        x,
        y,
        z: Fe::ONE,
        t,
    })
}

/// `sqrt(u/v)` per RFC 8032: candidate `x = (u/v)^((p+3)/8)`, then fix up with
/// the curve's `sqrt(-1)`. Returns `None` if no square root exists.
fn sqrt_ratio(u: Fe, v: Fe) -> Option<Fe> {
    let v3 = v.sq().mul(v);
    let v7 = v3.sq().mul(v);
    // (p+5)/8 exponent for u * v7 raised; build candidate.
    let exp = [
        0xfffffffffffffffd,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x0fffffffffffffff,
    ];
    let mut x = u.mul(v7).pow(exp).mul(u).mul(v3);

    let vx2 = v.mul(x.sq());
    let check = vx2.sub(u);
    if check.canonical() == Fe::ZERO {
        return Some(x);
    }
    let check2 = vx2.add(u);
    if check2.canonical() == Fe::ZERO {
        x = x.mul(sqrt_m1());
        return Some(x);
    }
    None
}

/// `sqrt(-1) mod p` = `2^((p-1)/4)`.
fn sqrt_m1() -> Fe {
    let exp = [
        0xfffffffffffffffb,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x1fffffffffffffff,
    ];
    Fe::from_u64(2).pow(exp)
}

// ---------------------------------------------------------------------------
// Scalars mod L = 2^252 + 27742317777372353535851937790883648493.
// ---------------------------------------------------------------------------

const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// Reduce a little-endian 64-byte integer mod L, returning 32 little-endian bytes.
fn reduce_scalar_wide(bytes: &[u8; 64]) -> [u8; 32] {
    // Bit-by-bit modular reduction: r = (r<<1 | bit) mod L, MSB first. L is
    // 253-bit, so r stays < L (fits in 4 limbs after each conditional subtract).
    let mut r = [0u64; 4];
    for i in (0..512).rev() {
        // r <<= 1
        let mut carry = 0u64;
        for limb in r.iter_mut() {
            let new_carry = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = new_carry;
        }
        // Set low bit from the source.
        let bit = (bytes[i / 8] >> (i % 8)) & 1;
        r[0] |= bit as u64;
        // If r >= L (or the shift overflowed 256 bits), subtract L.
        if carry != 0 || !less_than(r, L) {
            let (s, _) = sub_limbs(r, L);
            r = s;
        }
    }
    limbs_to_le(r)
}

/// `(a*b + c) mod L`, all 32-byte little-endian scalars.
fn scalar_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let al = le_to_limbs(a);
    let bl = le_to_limbs(b);
    let prod = mul_wide(al, bl); // 8 limbs = a*b (both < L < 2^253, product < 2^506)
    let mut wide = [0u8; 64];
    for (i, limb) in prod.iter().enumerate() {
        wide[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    let ab = reduce_scalar_wide(&wide); // (a*b) mod L
                                        // Add c mod L.
    let (sum, carry) = add_limbs(le_to_limbs(&ab), le_to_limbs(c));
    let mut r = sum;
    if carry != 0 || !less_than(r, L) {
        let (s, _) = sub_limbs(r, L);
        r = s;
    }
    limbs_to_le(r)
}

/// Whether the little-endian scalar `s` is `< L`.
fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    less_than(le_to_limbs(s), L)
}

fn less_than(a: [u64; 4], b: [u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

fn le_to_limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&b[i * 8..i * 8 + 8]);
        *limb = u64::from_le_bytes(buf);
    }
    limbs
}

fn limbs_to_le(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Ed25519 sign / verify (RFC 8032).
// ---------------------------------------------------------------------------

/// The 32-byte public key for a 32-byte secret seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    clamp(&mut a);
    Point::base().scalar_mul(&a).encode()
}

/// Sign `msg` with the 32-byte secret `seed`, returning the 64-byte signature.
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    clamp(&mut a);
    let prefix = &h[32..64];
    let public = Point::base().scalar_mul(&a).encode();

    // r = SHA512(prefix || msg) mod L
    let mut r_input = Vec::with_capacity(32 + msg.len());
    r_input.extend_from_slice(prefix);
    r_input.extend_from_slice(msg);
    let r = reduce_scalar_wide(&sha512(&r_input));
    let r_point = Point::base().scalar_mul(&r).encode();

    // k = SHA512(R || A || msg) mod L
    let mut k_input = Vec::with_capacity(64 + msg.len());
    k_input.extend_from_slice(&r_point);
    k_input.extend_from_slice(&public);
    k_input.extend_from_slice(msg);
    let k = reduce_scalar_wide(&sha512(&k_input));

    // S = (r + k*a) mod L
    let s = scalar_muladd(&k, &a, &r);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_point);
    sig[32..].copy_from_slice(&s);
    sig
}

/// Verify a 64-byte Ed25519 `sig` over `msg` under the 32-byte `public` key.
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut r_enc = [0u8; 32];
    r_enc.copy_from_slice(&sig[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);
    if !scalar_is_canonical(&s) {
        return false; // S must be reduced mod L
    }
    let Some(a_point) = decode(public) else {
        return false;
    };
    let Some(r_point) = decode(&r_enc) else {
        return false;
    };

    // k = SHA512(R || A || msg) mod L
    let mut k_input = Vec::with_capacity(64 + msg.len());
    k_input.extend_from_slice(&r_enc);
    k_input.extend_from_slice(public);
    k_input.extend_from_slice(msg);
    let k = reduce_scalar_wide(&sha512(&k_input));

    // Check [S]B == R + [k]A.
    let lhs = Point::base().scalar_mul(&s);
    let rhs = r_point.add(&a_point.scalar_mul(&k));
    lhs.encode() == rhs.encode()
}

/// Clamp the lower half of the expanded secret per RFC 8032.
fn clamp(a: &mut [u8; 32]) {
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
}

// ---------------------------------------------------------------------------
// Unpadded base64 (Matrix's key/signature encoding) + string wrappers.
// ---------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard-alphabet base64 without padding.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 63) as usize] as char);
        }
    }
    out
}

/// Decode standard-alphabet base64 (with or without padding).
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn b64_to_32(s: &str) -> Option<[u8; 32]> {
    let v = base64_decode(s)?;
    if v.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Some(a)
}

/// Derive a deterministic 32-byte seed from arbitrary `material` (the scaffold's
/// stand-in for a CSPRNG-generated key), returned as unpadded base64.
pub fn seed_from_material(material: &str) -> String {
    let h = sha512(material.as_bytes());
    base64_encode(&h[..32])
}

/// The unpadded-base64 public key for a base64 secret seed, or `None` if the
/// seed is not 32 bytes.
pub fn public_key_b64(seed_b64: &str) -> Option<String> {
    let seed = b64_to_32(seed_b64)?;
    Some(base64_encode(&public_key(&seed)))
}

/// Sign `msg` with a base64 secret seed, returning the base64 signature (empty
/// string if the seed is malformed).
pub fn sign_b64(msg: &[u8], seed_b64: &str) -> String {
    match b64_to_32(seed_b64) {
        Some(seed) => base64_encode(&sign(&seed, msg)),
        None => String::new(),
    }
}

/// Verify a base64 `sig` over `msg` under a base64 `public` key.
pub fn verify_b64(msg: &[u8], sig_b64: &str, public_b64: &str) -> bool {
    let (Some(public), Some(sig_bytes)) = (b64_to_32(public_b64), base64_decode(sig_b64)) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    verify(&public, msg, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn sha512_matches_known_vectors() {
        // SHA-512("") and SHA-512("abc") from FIPS 180-4.
        assert_eq!(
            sha512(b""),
            <[u8; 64]>::try_from(
                hex(
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                )
                .as_slice()
            )
            .unwrap()
        );
        assert_eq!(
            sha512(b"abc"),
            <[u8; 64]>::try_from(
                hex(
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                )
                .as_slice()
            )
            .unwrap()
        );
    }

    fn arr32(h: &str) -> [u8; 32] {
        <[u8; 32]>::try_from(hex(h).as_slice()).unwrap()
    }
    fn arr64(h: &str) -> [u8; 64] {
        <[u8; 64]>::try_from(hex(h).as_slice()).unwrap()
    }

    #[test]
    fn rfc8032_test1_signature_verifies() {
        // RFC 8032 §7.1 TEST 1 (public key + signature over the empty message).
        // `verify` checks these independently of the secret seed, exercising
        // point decompression, scalar multiplication, the hash, and the group
        // equation against an externally-produced signature.
        let public = arr32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = arr64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert!(verify(&public, b"", &sig));
        // A different message, or a flipped signature byte, must not verify.
        assert!(!verify(&public, b"x", &sig));
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(&public, b"", &bad));
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let seed = arr32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let public = public_key(&seed);
        // Public key derivation is deterministic.
        assert_eq!(public, public_key(&seed));

        let msg = b"the rain in spain";
        let sig = sign(&seed, msg);
        assert!(verify(&public, msg, &sig));
        // Wrong message, wrong key, or tampered signature all fail.
        assert!(!verify(&public, b"other", &sig));
        assert!(!verify(
            &public_key(&arr32(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )),
            msg,
            &sig
        ));
        let mut bad = sig;
        bad[40] ^= 0x80;
        assert!(!verify(&public, msg, &bad));
    }

    #[test]
    fn base64_round_trips_and_wrappers_sign_verify() {
        let data = b"\x00\x01\x02\xfe\xff hello base64";
        assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);

        let seed_b64 = seed_from_material("gaussian.tech:ed25519:1");
        let public_b64 = public_key_b64(&seed_b64).unwrap();
        let msg = b"federation request bytes";
        let sig_b64 = sign_b64(msg, &seed_b64);
        assert!(verify_b64(msg, &sig_b64, &public_b64));
        assert!(!verify_b64(b"tampered", &sig_b64, &public_b64));
        // A malformed seed signs to the empty string, which does not verify.
        assert!(sign_b64(msg, "not-base64!").is_empty());
    }
}
