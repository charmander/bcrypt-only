extern crate std;

use core::hash::Hasher;
use std::collections::hash_map::DefaultHasher;

use super::{Salt, WorkFactor, bcrypt};
use super::BcryptError::{Length, ZeroByte};

#[test]
fn pyca_test_vectors() {
	let test_vectors: [(&[u8], u32, &[u8; 16], &[u8; 23]); 26] = include!("pyca-test-vectors.in");

	for &(key, log_rounds, salt, expected_hash) in &test_vectors {
		assert_eq!(bcrypt(key, &Salt::from_bytes(salt), WorkFactor::exp(log_rounds).unwrap()), Ok(*expected_hash));
	}
}

#[test]
fn invalid_inputs() {
	let salt = Salt::from_bytes(&[0; 16]);
	let work_factor = WorkFactor::exp(4).unwrap();
	assert_eq!(bcrypt(&[1; 73], &salt, work_factor), Err(Length));
	assert_eq!(bcrypt(b"f\0o", &salt, work_factor), Err(ZeroByte));
}

#[test]
fn salt_round_trip() {
	for i in 0..2048 {
		let mut bytes = [0_u8; 16];

		let mut s = DefaultHasher::new();
		s.write_u32(i);
		bytes[0..8].copy_from_slice(&s.finish().to_ne_bytes());
		s.write_u32(i);
		bytes[8..16].copy_from_slice(&s.finish().to_ne_bytes());

		assert_eq!(Salt::from_bytes(&bytes).to_bytes(), bytes);
	}
}

#[test]
fn work_factors() {
	assert_eq!(WorkFactor::exp(3), None);
	assert_eq!(WorkFactor::exp(4).map(|f| f.log_rounds()), Some(4));
	assert_eq!(WorkFactor::exp(31).map(|f| f.linear_rounds()), Some(2147483648));
	assert_eq!(WorkFactor::exp(32), None);
}
