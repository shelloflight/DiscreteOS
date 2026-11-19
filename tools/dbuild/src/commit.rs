//! Interactive contributor-friendly `dbuild commit`:
//! stages changes, collects commit message, optionally invokes a local git-ignored hook,
//! prompts for DCO sign-off (`-s`), commits, and optionally pushes to the remote.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use crate::tools::{Env, find_in_path, run_capture, run_cmd};

#[derive(Default)]
pub struct CommitOpts {
    pub all: bool,
    pub message: Option<String>,
    pub body: Option<String>,
    pub signoff: Option<bool>,
    pub push: Option<bool>,
    pub yes: bool,
}

fn prompt_line(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("read stdin: {e}"))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool, String> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        let ans = prompt_line(&format!("{prompt} {suffix} "))?;
        let lower = ans.trim().to_ascii_lowercase();
        if lower.is_empty() {
            return Ok(default_yes);
        }
        match lower.as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y or n."),
        }
    }
}

fn run_local_hook(env: &Env, subject: &str, body: &str) -> Result<Option<String>, String> {
    #[cfg(windows)]
    {
        let hook = env.root.join("tools").join("commit-hook.ps1");
        if hook.is_file()
            && let Some(ps) = find_in_path("pwsh").or_else(|| find_in_path("powershell"))
        {
            let hook_s = hook.to_string_lossy();
            let out = run_capture(
                &ps,
                &[
                    "-NoProfile",
                    "-File",
                    &hook_s,
                    "-Subject",
                    subject,
                    "-Body",
                    body,
                ],
                Some(&env.root),
                &[],
            )?;
            let trimmed = out.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
    }
    #[cfg(not(windows))]
    {
        let hook = env.root.join("tools").join("commit-hook.sh");
        if hook.is_file()
            && let Some(sh) = find_in_path("sh")
        {
            let hook_s = hook.to_string_lossy();
            let out = run_capture(&sh, &[&hook_s, subject, body], Some(&env.root), &[])?;
            let trimmed = out.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.to_string()));
            }
        }
    }
    Ok(None)
}

fn current_branch_and_remote(git: &Path, root: &Path) -> (String, String) {
    let branch = run_capture(git, &["rev-parse", "--abbrev-ref", "HEAD"], Some(root), &[])
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "HEAD".into());
    let key = format!("branch.{branch}.remote");
    let remote = run_capture(git, &["config", "--get", &key], Some(root), &[])
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "origin".into());
    (branch, remote)
}

pub fn run_commit(env: &Env, opts: &CommitOpts) -> Result<(), String> {
    let git = find_in_path("git").ok_or_else(|| "git not found on PATH".to_string())?;

    let status = run_capture(&git, &["status", "--short"], Some(&env.root), &[])?;
    if status.trim().is_empty() {
        println!("Working tree clean — nothing to commit.");
        return Ok(());
    }

    println!("Changes in working tree:");
    print!("{status}");

    let stage_all = if opts.all || opts.yes {
        true
    } else {
        prompt_yes_no("Stage all changes (git add -A)?", true)?
    };
    if stage_all {
        run_cmd(&git, &["add".into(), "-A".into()], Some(&env.root), &[], false)?;
    }

    let staged = run_capture(&git, &["diff", "--cached", "--name-only"], Some(&env.root), &[])?;
    if staged.trim().is_empty() {
        return Err("Nothing staged to commit.".into());
    }

    let subject = match &opts.message {
        Some(m) if !m.trim().is_empty() => m.trim().to_string(),
        _ => loop {
            let s = prompt_line("Commit message (subject): ")?;
            if !s.trim().is_empty() {
                break s.trim().to_string();
            }
            println!("Commit message cannot be empty.");
        },
    };

    let body = match &opts.body {
        Some(b) => b.trim().to_string(),
        None if opts.message.is_some() || opts.yes => String::new(),
        None => {
            println!("Body (optional — press Enter on a blank line to skip/finish):");
            let mut lines = Vec::new();
            loop {
                let l = prompt_line("> ")?;
                if l.is_empty() {
                    break;
                }
                lines.push(l);
            }
            lines.join("\n")
        }
    };

    let mut full_msg = if let Some(hook_msg) = run_local_hook(env, &subject, &body)? {
        hook_msg
    } else if body.is_empty() {
        subject
    } else {
        format!("{subject}\n\n{body}")
    };
    if !full_msg.ends_with('\n') {
        full_msg.push('\n');
    }

    let signoff = match opts.signoff {
        Some(b) => b,
        None if opts.yes => true,
        None => prompt_yes_no("Sign off commit (DCO, git commit -s)?", true)?,
    };

    let (branch, remote) = current_branch_and_remote(&git, &env.root);
    println!("\n--- Commit preview (branch: {branch}, sign-off: {}) ---", if signoff { "yes" } else { "no" });
    print!("{full_msg}");
    println!("---");

    if !opts.yes && !prompt_yes_no("Commit?", true)? {
        println!("Aborted.");
        return Ok(());
    }

    let tmp = std::env::temp_dir().join(format!("dbuild-commit-{}.txt", std::process::id()));
    fs::write(&tmp, &full_msg).map_err(|e| format!("write temp commit msg: {e}"))?;
    let mut commit_args = vec!["commit".into()];
    if signoff {
        commit_args.push("-s".into());
    }
    commit_args.push("-F".into());
    commit_args.push(tmp.to_string_lossy().into_owned());
    let commit_res = run_cmd(&git, &commit_args, Some(&env.root), &[], false);
    let _ = fs::remove_file(&tmp);
    commit_res?;

    let do_push = match opts.push {
        Some(b) => b,
        None if opts.yes => false,
        None => prompt_yes_no(&format!("Push '{branch}' to '{remote}'?"), true)?,
    };
    if do_push {
        run_cmd(&git, &["push".into()], Some(&env.root), &[], false)?;
    }

    Ok(())
}
