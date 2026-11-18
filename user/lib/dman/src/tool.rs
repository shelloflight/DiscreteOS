//! Tool manifests (`kind = "tool"`): a program the shell runs, its names and its parameters with
//! the rights each one needs (docs/shell.md). The shell gives a tool exactly these, nothing else.
//!
//! ```toml
//! kind = "tool"
//! name = "copy"
//! image = "copy.dx"
//! aliases = ["cp"]
//! description = "copy a file"
//!
//! [parameters]            # in order; the last one may take several values ("many")
//! from = "path:read"
//! to = "path:write,create"
//!
//! [about]                 # optional: one line per parameter, for `help copy`
//! from = "the file to copy"
//! to = "where the copy goes (a directory keeps the name)"
//! ```
//!
//! A parameter is `path`, `text` or `number`, then flags after a colon: `read`, `write` (paths:
//! the rights; write includes read), `create` (the path may not exist yet; needs write),
//! `optional`, `many` (last parameter only).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::toml::{self, Error, Value, err};
use crate::{valid_name, valid_program};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamKind {
    Path,
    Text,
    Number,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub kind: ParamKind,
    /// Paths: the rights the tool gets on it.
    pub read: bool,
    pub write: bool,
    /// Paths: it may not exist yet (the tool gets the directory it goes in).
    pub create: bool,
    pub optional: bool,
    /// Takes every remaining value (the last parameter only).
    pub many: bool,
    /// One line for `help`.
    pub about: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    pub image: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub params: Vec<Param>,
}

/// Is this manifest a tool's (`kind = "tool"` at the top)? Decided without the full schema, so
/// either parser reports the problems of its own kind.
pub fn is_tool(src: &[u8]) -> bool {
    toml::parse(src).is_ok_and(|d| d.entries.iter().any(|e| e.table.is_empty() && e.key == "kind" && e.value == Value::Str("tool".into())))
}

fn parse_param(name: &str, spec: &str, line: u32) -> Result<Param, Error> {
    let (kind, flags) = spec.split_once(':').unwrap_or((spec, ""));
    let kind = match kind {
        "path" => ParamKind::Path,
        "text" => ParamKind::Text,
        "number" => ParamKind::Number,
        _ => return Err(err(line, format!("'parameters.{}': unknown kind '{}' (path, text, number)", name, kind))),
    };
    let mut p = Param { name: name.to_string(), kind, read: false, write: false, create: false, optional: false, many: false, about: String::new() };
    for f in flags.split(',').filter(|f| !f.is_empty()) {
        let slot = match f {
            "read" => &mut p.read,
            "write" => &mut p.write,
            "create" => &mut p.create,
            "optional" => &mut p.optional,
            "many" => &mut p.many,
            _ => return Err(err(line, format!("'parameters.{}': unknown flag '{}' (read, write, create, optional, many)", name, f))),
        };
        if *slot {
            return Err(err(line, format!("'parameters.{}': flag '{}' given twice", name, f)));
        }
        *slot = true;
    }
    if kind == ParamKind::Path {
        p.read |= p.write; // writing a file needs reading it (sizes, directory checks)
        if !p.read {
            return Err(err(line, format!("'parameters.{}': a path needs read or write", name)));
        }
        if p.create && !p.write {
            return Err(err(line, format!("'parameters.{}': create needs write", name)));
        }
    } else if p.read || p.write || p.create {
        return Err(err(line, format!("'parameters.{}': rights apply to paths only", name)));
    }
    Ok(p)
}

/// Read a tool manifest. Unknown keys and tables refuse it, with the line and key named.
pub fn parse(src: &[u8]) -> Result<Tool, Error> {
    let doc = toml::parse(src)?;
    if let Some((t, line)) = doc.tables.iter().find(|(t, _)| !matches!(t.as_str(), "parameters" | "about")) {
        return Err(err(*line, format!("unknown table [{}]", t)));
    }
    let mut t = Tool { name: String::new(), image: String::new(), aliases: Vec::new(), description: String::new(), params: Vec::new() };
    let mut kind = false;
    let mut about: Vec<(String, String, u32)> = Vec::new();
    for e in &doc.entries {
        let fk = if e.table.is_empty() { e.key.clone() } else { format!("{}.{}", e.table, e.key) };
        let string = || match &e.value {
            Value::Str(s) => Ok(s.clone()),
            v => Err(err(e.line, format!("'{}' must be a string, not {}", fk, v.type_name()))),
        };
        match (e.table.as_str(), e.key.as_str()) {
            ("", "kind") => {
                if string()? != "tool" {
                    return Err(err(e.line, "'kind' must be \"tool\""));
                }
                kind = true;
            }
            ("", "name") => {
                let s = string()?;
                if !valid_name(&s) {
                    return Err(err(e.line, format!("'name': not a valid name (a-z 0-9 -, at most 24) '{}'", s)));
                }
                t.name = s;
            }
            ("", "image") => {
                let s = string()?;
                if !valid_program(&s) || !s.ends_with(".dx") {
                    return Err(err(e.line, format!("'image': not a program name (<name>.dx) '{}'", s)));
                }
                t.image = s;
            }
            ("", "description") => t.description = string()?,
            ("", "aliases") => {
                let Value::Array(a) = &e.value else { return Err(err(e.line, "'aliases' must be an array of strings")) };
                for v in a {
                    let Value::Str(s) = v else { return Err(err(e.line, "'aliases' must be an array of strings")) };
                    if !valid_name(s) || t.aliases.contains(s) {
                        return Err(err(e.line, format!("'aliases': not a valid name, or listed twice: '{}'", s)));
                    }
                    t.aliases.push(s.clone());
                }
            }
            ("parameters", name) => {
                if !valid_name(name) {
                    return Err(err(e.line, format!("'{}': not a valid parameter name", fk)));
                }
                if let Some(last) = t.params.last()
                    && last.many
                {
                    return Err(err(e.line, format!("'{}': only the last parameter may be 'many'", fk)));
                }
                if let Some(last) = t.params.last()
                    && last.optional
                {
                    return Err(err(e.line, format!("'{}': a parameter cannot follow an optional one", fk)));
                }
                t.params.push(parse_param(name, &string()?, e.line)?);
            }
            ("about", name) => about.push((name.to_string(), string()?, e.line)),
            _ => return Err(err(e.line, format!("unknown key '{}'", fk))),
        }
    }
    if !kind {
        return Err(err(0, "missing 'kind' (\"tool\")"));
    }
    if t.name.is_empty() {
        return Err(err(0, "missing 'name'"));
    }
    if t.image.is_empty() {
        return Err(err(0, "missing 'image'"));
    }
    if t.params.len() > 8 || t.aliases.len() > 8 {
        return Err(err(0, "more than 8 parameters or aliases"));
    }
    for (name, text, line) in about {
        let Some(p) = t.params.iter_mut().find(|p| p.name == name) else {
            return Err(err(line, format!("'about.{}': no such parameter", name)));
        };
        p.about = text;
    }
    Ok(t)
}

impl Tool {
    /// The usage line: `copy <from> <to>`, `list [place]`, `delete <path>...`.
    pub fn usage(&self) -> String {
        let mut s = self.name.clone();
        for p in &self.params {
            let n = if p.optional { format!(" [{}]", p.name) } else { format!(" <{}>", p.name) };
            s.push_str(&n);
            if p.many {
                s.push_str("...");
            }
        }
        s
    }
}
