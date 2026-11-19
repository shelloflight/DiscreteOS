//! Pure `no_std`, zero-allocation, zero-unsafe audio core for D-OS.
//!
//! - `pcm`: sample formats (`U8`, `S16Le`, `S24Le`, `S32Le`, `F32Le`), channel mapping,
//!   stateful linear resampler, saturating mixer, and fixed-point sine tone generator.
//! - `route`: output device classification and automatic output switching policy
//!   (headphones -> USB audio -> HDMI/DP -> speakers/line-out).
//! - `hda_graph`: dynamic Intel HD Audio codec/widget/pin graph discovery (no board tables)
//!   and HDMI/DisplayPort ELD parser.
//! - `uac`: USB Audio Class 1.0 and 2.0 configuration descriptor parser.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod hda_graph;
pub mod pcm;
pub mod route;
pub mod uac;

#[cfg(test)]
mod tests;
