//! # Storage Layout
//!
//! ## uint128 (finite field element)
//! `position` にある 4 つの要素に 32 bits ずつ格納する.
//!
//! ## vector
//! vector の `index` 番目の要素は
//! `get_index_position(position, index)` 番目に格納する.
//! また,　vector の長さを `position` に格納する.
//!
//! ## mapping
//! mapping の `key` に対応する値は
//! `get_key_position(position, key)` 番目に格納する.
//!
//! ## bytes
//! bytes data は 32 bytes ごとに区切って,
//! `get_index_position(position, index)` 番目から順番に格納していく (Big Endian).
//! また, bytes data の長さを `position` に格納する.

pub mod types;

pub mod tree;

pub mod layered_tree;

pub mod layered_layered_tree;
