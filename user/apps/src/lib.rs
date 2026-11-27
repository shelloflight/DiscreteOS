//! D-OS core native GUI applications (`files`, `editor`, `settings`, `sysmon`, `installer`, `oobe`).

#![no_std]

extern crate alloc;

mod common;
mod editor;
mod files;
mod installer;
mod oobe;
mod settings;
mod sysmon;

libd::entry!(dx_files, files::main);
libd::entry!(dx_editor, editor::main);
libd::entry!(dx_settings, settings::main);
libd::entry!(dx_sysmon, sysmon::main);
libd::entry!(dx_installer, installer::main);
libd::entry!(dx_oobe, oobe::main);
