# bcrypt-only

Just the low-level bcrypt function from a 0–72-byte key, 16-byte salt, and work factor to a 23-byte hash. Implemented in safe Rust. Doesn’t yet zero memory.

If you want to generate or verify password hashes with this, you should look at [bcrypt-small][].


  [bcrypt-small]: https://docs.rs/bcrypt-small/
