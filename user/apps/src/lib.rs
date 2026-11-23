//! D-OS core native GUI applications (`files`, `editor`, `settings`, `sysmon`).

#![no_std]

extern crate alloc;

mod common;
mod editor;
mod files;
mod settings;
mod sysmon;

libd::entry!(dx_files, files::main);
libd::entry!(dx_editor, editor::main);
libd::entry!(dx_settings, settings::main);
libd::entry!(dx_sysmon, sysmon::main);
