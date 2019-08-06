#![no_std]

#[cfg(test)]
mod tests;

/// The maximum number of bytes in a bcrypt key.
pub const KEY_SIZE_MAX: usize = 72;

/// The number of bytes in a bcrypt salt.
pub const SALT_SIZE: usize = 16;

/// The number of bytes in a bcrypt hash.
pub const HASH_SIZE: usize = 23;

/// A bcrypt work factor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkFactor(u32);

/// A bcrypt hashing error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BcryptError {
	/// The key was longer than the limit of 72 bytes.
	Length,

	/// The key contained a 0 byte.
	ZeroByte,
}

/// A bcrypt salt.
#[derive(Clone, Debug)]
pub struct Salt {
	be: [u32; 4],
}

impl Salt {
	/// Creates a bcrypt salt from any 16 bytes.
	pub fn from_bytes(bytes: &[u8; SALT_SIZE]) -> Self {
		let mut be = [0_u32; 4];

		for i in 0..4 {
			be[i] = u32::from_be_bytes([
				bytes[4 * i],
				bytes[4 * i + 1],
				bytes[4 * i + 2],
				bytes[4 * i + 3],
			]);
		}

		Self { be }
	}

	/// Gets the bytes making up a bcrypt salt.
	pub fn to_bytes(&self) -> [u8; SALT_SIZE] {
		let mut bytes = [0_u8; 16];

		for (b, w) in bytes.chunks_exact_mut(4).zip(self.be.iter().copied()) {
			b.copy_from_slice(&w.to_be_bytes());
		}

		bytes
	}
}

impl WorkFactor {
	/// Creates a bcrypt work factor from a typical base-2 exponent between 4 and 31 (inclusive). The number of rounds is 2\*\*`log_rounds`.
	pub fn exp(log_rounds: u32) -> Option<Self> {
		if log_rounds >= 4 && log_rounds <= 31 {
			Some(Self(log_rounds))
		} else {
			None
		}
	}

	/// The base-2 logarithm of the number of rounds represented by this work factor.
	pub const fn log_rounds(self) -> u32 {
		self.0
	}

	/// The number of rounds represented by this work factor.
	pub const fn linear_rounds(self) -> u32 {
		1 << self.0
	}
}

const BLF_N: usize = 16;

const BLOWFISH_INITIAL: BlowfishContext = BlowfishContext {
	s: include!("sbox-init.in"),
	p: [
		0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
		0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
		0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
		0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
		0x9216d5d9, 0x8979fb1b,
	],
};

const BCRYPT_MESSAGE: [u32; 6] = {
	const fn u32_from_be_bytes(bytes: [u8; 4]) -> u32 {
		(bytes[0] as u32) << 24
		| (bytes[1] as u32) << 16
		| (bytes[2] as u32) << 8
		| (bytes[3] as u32)
	}

	[
		u32_from_be_bytes(*b"Orph"),
		u32_from_be_bytes(*b"eanB"),
		u32_from_be_bytes(*b"ehol"),
		u32_from_be_bytes(*b"derS"),
		u32_from_be_bytes(*b"cryD"),
		u32_from_be_bytes(*b"oubt"),
	]
};

#[derive(Clone)]
struct BlowfishContext {
	s: [[u32; 256]; 4],  // S-Boxes
	p: [u32; BLF_N + 2], // subkeys
}

fn read_u32_be<T: Iterator<Item = u8>>(bytes: &mut T) -> u32 {
	u32::from(bytes.next().unwrap()) << 24
	| u32::from(bytes.next().unwrap()) << 16
	| u32::from(bytes.next().unwrap()) << 8
	| u32::from(bytes.next().unwrap())
}

fn f(c: &BlowfishContext, x: u32) -> u32 {
	let [b0, b1, b2, b3] = x.to_be_bytes();
	let h = c.s[0][usize::from(b0)].wrapping_add(c.s[1][usize::from(b1)]);
	(h ^ c.s[2][usize::from(b2)]).wrapping_add(c.s[3][usize::from(b3)])
}

fn blowfish_encipher(c: &BlowfishContext, mut l: u32, mut r: u32) -> (u32, u32) {
	for i in (0..16).step_by(2) {
		l ^= c.p[i];
		r ^= f(c, l);
		r ^= c.p[i + 1];
		l ^= f(c, r);
	}

	l ^= c.p[16];
	r ^= c.p[17];

	(r, l)
}

/// An iterator yielding the bytes of a key, then 0, forever.
struct KeyCycle<'a> {
	key: &'a [u8],
	index: usize,
}

impl<'a> Iterator for KeyCycle<'a> {
	type Item = u8;

	fn next(&mut self) -> Option<u8> {
		if self.index == self.key.len() {
			self.index = 0;
			return Some(0);
		}

		let result = self.key[self.index];
		self.index += 1;
		Some(result)
	}
}

fn blowfish_expandstate_key(c: &mut BlowfishContext, key: &[u8]) {
	let mut key_cycle = KeyCycle { key, index: 0 };

	for pi in &mut c.p {
		let temp = read_u32_be(&mut key_cycle);
		*pi ^= temp;
	}
}

fn blowfish_expandstate_data(c: &mut BlowfishContext, data: &[u32; 4]) {
	let mut datal = 0_u32;
	let mut datar = 0_u32;

	for i in (0..BLF_N + 2).step_by(2) {
		datal ^= data[i % 4];
		datar ^= data[i % 4 + 1];
		let (nextl, nextr) = blowfish_encipher(c, datal, datar);
		datal = nextl;
		datar = nextr;

		c.p[i] = datal;
		c.p[i + 1] = datar;
	}

	for i in 0..4 {
		for k in (0..256).step_by(2) {
			datal ^= data[(k + 2) % 4];
			datar ^= data[(k + 2) % 4 + 1];
			let (nextl, nextr) = blowfish_encipher(c, datal, datar);
			datal = nextl;
			datar = nextr;

			c.s[i][k] = datal;
			c.s[i][k + 1] = datar;
		}
	}
}

fn blowfish_expandstate_data0(c: &mut BlowfishContext) {
	let mut datal = 0_u32;
	let mut datar = 0_u32;

	for i in (0..BLF_N + 2).step_by(2) {
		let (nextl, nextr) = blowfish_encipher(c, datal, datar);
		datal = nextl;
		datar = nextr;

		c.p[i] = datal;
		c.p[i + 1] = datar;
	}

	for i in 0..4 {
		for k in (0..256).step_by(2) {
			let (nextl, nextr) = blowfish_encipher(c, datal, datar);
			datal = nextl;
			datar = nextr;

			c.s[i][k] = datal;
			c.s[i][k + 1] = datar;
		}
	}
}

/// Hashes a key and salt with bcrypt according to a work factor. The key can’t be longer than 72 bytes and can’t contain a 0 byte.
pub fn bcrypt(key: &[u8], salt: &Salt, work_factor: WorkFactor) -> Result<[u8; HASH_SIZE], BcryptError> {
	if key.len() > KEY_SIZE_MAX {
		return Err(BcryptError::Length);
	}

	if key.contains(&b'\0') {
		return Err(BcryptError::ZeroByte);
	}

	let mut state = BLOWFISH_INITIAL;

	blowfish_expandstate_key(&mut state, key);
	blowfish_expandstate_data(&mut state, &salt.be);

	for _ in 0..work_factor.linear_rounds() {
		blowfish_expandstate_key(&mut state, key);
		blowfish_expandstate_data0(&mut state);

		for i in 0..(BLF_N + 2) {
			state.p[i] ^= salt.be[i % 4];
		}

		blowfish_expandstate_data0(&mut state);
	}

	let mut cdata = BCRYPT_MESSAGE;

	for _ in 0..64 {
		for i in (0..BCRYPT_MESSAGE.len()).step_by(2) {
			let (l, r) = blowfish_encipher(&state, cdata[i], cdata[i + 1]);
			cdata[i] = l;
			cdata[i + 1] = r;
		}
	}

	let mut result = [0_u8; 23];

	for (b, w) in result.chunks_exact_mut(4).zip(cdata.iter().copied()) {
		b.copy_from_slice(&w.to_be_bytes());
	}

	result[20..].copy_from_slice(&cdata[5].to_be_bytes()[0..3]);

	Ok(result)
}
