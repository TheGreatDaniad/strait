//! NAT Tunnel library: configuration, NAT traversal, remote access,
//! network simulation and terminal UI.

pub mod app;
pub mod birthday;
pub mod carrier;
pub mod config;
#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(feature = "gui")]
pub mod gui;
pub mod invite;
pub mod network;
pub mod preflight;
pub mod privileged;
pub mod relay;
pub mod rendezvous;
pub mod remote;
pub mod transport;
#[cfg(not(any(target_os = "android", target_os = "ios", all(feature = "ffi", target_os = "macos"))))]
pub mod tunmode;
#[cfg(any(target_os = "ios", all(feature = "ffi", target_os = "macos")))]
#[path = "tunmode_fd.rs"]
pub mod tunmode;
#[cfg(target_os = "android")]
#[path = "tunmode_android.rs"]
pub mod tunmode;
pub mod tunnel;
pub mod ui;
pub mod upnp;
pub mod userspace;
