// Copyright 2023 git-rcrypt developers
// Copyright 2012, 2014 Andrew Ayer
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Error;
use std::io::Read;
use std::io::Write;

use ggstd::crypto::aes;
use ggstd::crypto::cipher::{self, Stream};
use ggstd::crypto::hmac::HMAC;
use ggstd::crypto::rand;
use ggstd::crypto::sha1;
use ggstd::encoding::binary::{ByteOrder, BIG_ENDIAN};
use ggstd::hash::Hash;
use std::process::{Command, Stdio};

const VERSION: &str = "0.0.1";

fn print_usage(program_name: &str, out: &mut dyn std::io::Write) {
    writeln!(
        out,
        "Usage: {} COMMAND [ARGS ...]

Common commands:
  init                 generate a key and prepare repo to use git-rcrypt
  lock                 de-configure git-rcrypt and re-encrypt files in work tree
  unlock KEYFILE       decrypt this repo using the given symmetric key
",
        program_name
    )
    .unwrap();
}

fn print_version(out: &mut dyn std::io::Write) {
    writeln!(out, "git-rcrypt {}", VERSION).unwrap();
}

fn help(program_name: &str, args: &[&str]) -> Result<(), Error> {
    if args.is_empty() {
        print_usage(program_name, &mut std::io::stdout());
    } else {
        let out = &mut std::io::stdout();
        let command = args[0];
        match command {
            "init" => help_init(out),
            "unlock" => help_unlock(out),
            "lock" => help_lock(out),
            _ => {
                eprint!(
                    "'{}' is not a git-rcrypt command. See 'git-rcrypt help'.",
                    args[0]
                );
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn version() -> Result<(), Error> {
    print_version(&mut std::io::stdout());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let (program_name, mut args) = (args[0], &args[1..]);

    let stderr = &mut std::io::stderr();

    while !args.is_empty() && args[0].starts_with('-') {
        if args[0] == "--help" {
            print_usage(program_name, stderr);
            return;
        } else if args[0] == "--version" {
            print_version(stderr);
            return;
        } else if args[0] == "--" {
            args = &args[1..];
            break;
        } else {
            eprintln!("{}: {}: Unknown option", program_name, args[0]);
            print_usage(program_name, stderr);
            std::process::exit(2);
        }
    }

    if args.is_empty() {
        print_usage(program_name, stderr);
        std::process::exit(2);
    }

    let command = args[0];
    let args = &args[1..];

    let res = match command {
        // Public commands:
        "help" => help(program_name, args),
        "version" => version(),
        "init" => init(args),
        "unlock" => unlock(args),
        "lock" => lock(args),
        // Plumbing commands (executed by git, not by user):
        "clean" => clean(args),
        "smudge" => smudge(args),
        "diff" => diff(args),
        _ => {
            eprintln!(
                "'{}' is not a git-rcrypt command. See 'git-rcrypt help'.",
                command
            );
            std::process::exit(1);
        }
    };

    if let Err(err) = res {
        eprintln!("git-rcrypt: {}", err);
        std::process::exit(2);
    }
}

const GITCRYPT_FILE_HEADER: &[u8; 10] = b"\0GITCRYPT\0";
const ENCRYPTED_FILE_MARKER_SIZE: usize = 10;
const NONCE_LEN: usize = 12;
const ENCRYPTED_FILE_HEADER_SIZE: usize = ENCRYPTED_FILE_MARKER_SIZE + NONCE_LEN;

fn git_config(name: &str, value: &str) -> std::io::Result<()> {
    exec_git(&["config", name, value], "'git config' failed")
}

fn git_has_config(name: &str) -> std::io::Result<bool> {
    let mut cmd = git_command(&["config", "--get-all", name]);
    let output = cmd.output()?;
    if output.status.success() {
        Ok(true)
    } else if output.status.code().is_some_and(|v| v == 1) {
        Ok(false)
    } else {
        Err(new_other_err("'git config' failed".to_string()))
    }
}

fn git_deconfig(name: &str) -> std::io::Result<()> {
    exec_git(&["config", "--remove-section", name], "'git config' failed")
}

fn configure_git_filters() -> std::io::Result<()> {
    let git_crypt_path = std::env::current_exe()?;
    let git_crypt_path = escape_shell_arg(&git_crypt_path.to_string_lossy());

    git_config(
        "filter.git-rcrypt.smudge",
        &format!("{} smudge", git_crypt_path),
    )?;
    git_config(
        "filter.git-rcrypt.clean",
        &format!("{} clean", git_crypt_path),
    )?;
    git_config("filter.git-rcrypt.required", "true")?;
    git_config(
        "diff.git-rcrypt.textconv",
        &format!("{} diff", git_crypt_path),
    )?;
    Ok(())
}

fn deconfigure_git_filters() -> std::io::Result<()> {
    // deconfigure the git-rcrypt filters
    if git_has_config("filter.git-rcrypt.smudge")?
        || git_has_config("filter.git-rcrypt.clean")?
        || git_has_config("filter.git-rcrypt.required")?
    {
        git_deconfig("filter.git-rcrypt")?;
    }

    if git_has_config("diff.git-rcrypt.textconv")? {
        git_deconfig("diff.git-rcrypt")?;
    }
    Ok(())
}

fn git_checkout(paths: &[String]) -> std::io::Result<()> {
    let mut input: Vec<u8> = Vec::new();
    for path in paths {
        input.extend_from_slice(path.as_bytes());
        input.push(0);
    }
    let output = launch_and_write_to_stdin(
        &[
            "git",
            "checkout",
            "--pathspec-from-file=-",
            "--pathspec-file-nul",
        ],
        &input,
    )?;
    if !output.status.success() {
        return Err(new_other_err(
            "failed to check out encrypted files - is this a Git repository?".to_string(),
        ));
    }
    Ok(())
}

fn get_internal_state_path() -> std::io::Result<String> {
    // git rev-parse --git-dir
    let output = exec_git_for_output(
        &["rev-parse", "--git-dir"],
        true,
        "'git rev-parse --git-dir' failed - is this a Git repository?",
    )?;
    if output.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "git dir is not found",
        ));
    }
    Ok(format!("{}/git-rcrypt", output))
}

fn get_internal_keys_path() -> std::io::Result<String> {
    Ok(format!("{}/keys", get_internal_state_path()?))
}

fn get_internal_key_path() -> std::io::Result<String> {
    Ok(format!("{}/default", get_internal_keys_path()?))
}

fn get_path_to_top() -> std::io::Result<String> {
    let output = exec_git_for_output(
        &["rev-parse", "--show-cdup"],
        true,
        "'git rev-parse --show-cdup' failed - is this a Git repository?",
    )?;
    Ok(if output.is_empty() {
        ".".to_string()
    } else {
        output
    })
}

fn get_git_status() -> std::io::Result<String> {
    exec_git_for_output(
        &["status", "-uno", "--porcelain"],
        true,
        "'git status' failed - is this a Git repository?",
    )
}

fn git_command(args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    cmd.args(args);
    cmd
}

/// exec_git runs git command.
/// If the exit status is not zero, then returns an error with the given message.
fn exec_git(args: &[&str], error_message: &str) -> std::io::Result<()> {
    let mut cmd = git_command(args);
    let status = cmd.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(new_other_err(error_message.to_string()))
    }
}

/// exec_git_for_bin_output runs git command and returns std out of the command.
/// If the exit status is not zero, then returns an error with the given message.
fn exec_git_for_bin_output(args: &[&str], error_message: &str) -> std::io::Result<Vec<u8>> {
    let mut cmd = git_command(args);
    let output = cmd.output()?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(new_other_err(error_message.to_string()))
    }
}

/// exec_git_for_output runs git command and returns std out of the command.
/// If the exit status is not zero, then returns an error with the given message.
fn exec_git_for_output(args: &[&str], trim: bool, error_message: &str) -> std::io::Result<String> {
    let output = exec_git_for_bin_output(args, error_message)?;
    let output_text = String::from_utf8_lossy(&output);
    if trim {
        Ok(output_text.trim().to_string())
    } else {
        Ok(output_text.to_string())
    }
}

/// Return list of files encrypted with the given key.
fn get_encrypted_files() -> std::io::Result<Vec<String>> {
    // TODO: check how this works with non-ascii file names (on Linux and on Windows)

    let mut files = Vec::new();

    let expected_filter_value = "git-rcrypt";

    let output = launch_two_processes(
        &["git", "ls-files", "-z", "--", &get_path_to_top()?],
        &["git", "check-attr", "--stdin", "-z", "filter"],
    )?;
    if !output.status.success() {
        return Err(new_other_err(
            "failed to list file attributes - is this a Git repository?".to_string(),
        ));
    }
    let mut s = output.stdout.split(|v| *v == 0);
    loop {
        let filename = s.next();
        let filter_name = s.next();
        let filter_value = s.next();
        if filename.is_none() || filter_name.is_none() || filter_value.is_none() {
            break;
        }
        let filename = String::from_utf8_lossy(filename.unwrap());
        let filter_name = String::from_utf8_lossy(filter_name.unwrap());
        let filter_value = String::from_utf8_lossy(filter_value.unwrap());
        if filter_name == "filter" && filter_value == expected_filter_value {
            files.push(filename.to_string());
        }
    }
    Ok(files)
}

fn load_key() -> std::io::Result<Key> {
    let key_path = std::path::PathBuf::from(get_internal_key_path()?);
    let mut f = std::fs::File::open(key_path)?;
    Key::load(&mut f)
}

fn encrypt_file(
    key: &Key,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    // Read the entire file into memory
    let mut data = Vec::with_capacity(4 * 1024 * 1024);
    r.read_to_end(&mut data)?;

    // Calculate hmac
    let mut hmac = HMAC::new(sha1::Digest::new, &key.hmac_key);
    hmac.write_all(&data).unwrap();
    let digest = hmac.sum(&[]);

    // Write a header that...
    w.write_all(b"\0GITCRYPT\0")?; // ...identifies this as an encrypted file
    w.write_all(&digest[..NONCE_LEN])?; // ...includes the nonce

    // Now encrypt the file
    let mut iv: [u8; 16] = [0; 16];
    iv[..NONCE_LEN].copy_from_slice(&digest[..NONCE_LEN]);

    let block = aes::Cipher::new(&key.aes_key).unwrap();
    let mut stream = cipher::CTR::new(&block, &iv);
    stream.xor_key_stream_inplace(&mut data);
    w.write_all(&data)?;
    w.flush()?;
    Ok(())
}

/// Encrypt contents of stdin and write to stdout
fn clean(args: &[&str]) -> Result<(), Error> {
    if !args.is_empty() {
        eprintln!("parameters to clean command are not supported");
        std::process::exit(1);
    }
    let key = load_key()?;
    encrypt_file(
        &key,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}

fn decrypt_file_after_header(
    key: &Key,
    nonce: &[u8],
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    assert_eq!(NONCE_LEN, nonce.len());
    let mut iv: [u8; 16] = [0; 16];
    iv[..NONCE_LEN].copy_from_slice(nonce);

    let block = aes::Cipher::new(&key.aes_key).unwrap();
    let mut stream = cipher::CTR::new(&block, &iv);
    let mut hmac = HMAC::new(sha1::Digest::new, &key.hmac_key);
    let mut buffer = vec![0; 4 * 1024 * 1024];
    loop {
        let n = r.read(&mut buffer)?;
        if n == 0 {
            // EOF
            break;
        }
        stream.xor_key_stream_inplace(&mut buffer[0..n]);
        hmac.write_all(&buffer[0..n]).unwrap();
        w.write_all(&buffer[0..n])?;
    }
    w.flush()?;

    let digest = hmac.sum(&[]);
    if iv[..NONCE_LEN] != digest[..NONCE_LEN] {
        return Err(new_other_err(
            "encrypted file has been tampered with!".to_string(),
        ));
    }
    Ok(())
}

/// Decrypt contents of stdin and write to stdout
fn smudge(args: &[&str]) -> Result<(), Error> {
    if !args.is_empty() {
        eprintln!("parameters to smudge command are not supported");
        std::process::exit(1);
    }
    let key = load_key()?;

    // Read the header to get the nonce and make sure it's actually encrypted
    let mut header = [0; ENCRYPTED_FILE_HEADER_SIZE];
    let mut r = std::io::stdin().lock();
    let n = r.read(&mut header)?;
    if n != ENCRYPTED_FILE_HEADER_SIZE
        || &header[..ENCRYPTED_FILE_MARKER_SIZE] != GITCRYPT_FILE_HEADER
    {
        eprintln!("git-rcrypt: Warning: file is not encrypted.");
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&header[..n])?;
        std::io::copy(&mut r, &mut stdout)?;
        Ok(())
    } else {
        decrypt_file_after_header(
            &key,
            &header[ENCRYPTED_FILE_MARKER_SIZE..ENCRYPTED_FILE_HEADER_SIZE],
            &mut r,
            &mut std::io::stdout().lock(),
        )
    }
}

fn diff(args: &[&str]) -> Result<(), Error> {
    if args.len() != 1 {
        eprintln!("parameters to diff command are not supported");
        std::process::exit(1);
    }
    let key = load_key()?;

    let mut r = std::fs::File::open(args[0])?;

    // Read the header to get the nonce and make sure it's actually encrypted
    let mut header = [0; ENCRYPTED_FILE_HEADER_SIZE];
    let n = r.read(&mut header)?;
    if n != ENCRYPTED_FILE_HEADER_SIZE
        || &header[..ENCRYPTED_FILE_MARKER_SIZE] != GITCRYPT_FILE_HEADER
    {
        // File not encrypted - just copy it out to stdout
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&header[..n])?;
        std::io::copy(&mut r, &mut stdout)?;
        std::process::exit(0);
    }

    decrypt_file_after_header(
        &key,
        &header[ENCRYPTED_FILE_MARKER_SIZE..ENCRYPTED_FILE_HEADER_SIZE],
        &mut r,
        &mut std::io::stdout().lock(),
    )?;
    Ok(())
}

fn help_init(w: &mut dyn std::io::Write) {
    writeln!(w, "Usage: git-rcrypt init").unwrap();
}

fn init(args: &[&str]) -> Result<(), Error> {
    if !args.is_empty() {
        eprintln!("Error: git-rcrypt init takes no arguments");
        help_init(&mut std::io::stderr().lock());
        std::process::exit(2);
    }

    let key_path = get_internal_key_path()?;
    if is_file(&key_path) {
        eprintln!("Error: this repository has already been initialized with git-rcrypt.");
        std::process::exit(1);
    }

    // 1. Generate a key and install it
    let key = Key::generate()?;
    std::fs::create_dir_all(get_internal_keys_path()?)?;
    key.store_to_file(key_path)?;

    // 2. Configure git for git-rcrypt
    configure_git_filters()?;
    Ok(())
}

fn help_unlock(w: &mut dyn std::io::Write) {
    writeln!(
        w,
        r#"Usage: git-rcrypt unlock KEY_FILE

If KEY_FILE is "-", the key will be read from the standard input.
"#
    )
    .unwrap();
}

fn unlock(args: &[&str]) -> Result<(), Error> {
    // 1. Make sure working directory is clean (ignoring untracked files)
    // We do this because we check out files later, and we don't want the
    // user to lose any changes.

    // Running 'git status' also serves as a check that the Git repo is accessible.
    let git_status_output = get_git_status()?;
    if !git_status_output.is_empty() {
        eprintln!("Working directory not clean.\nPlease commit your changes or 'git stash' them before running 'git-rcrypt unlock'.");
        std::process::exit(1);
    }

    // 2. Load the key(s)
    if args.is_empty() {
        eprintln!(r#"Path to the key file, or "-" is required."#);
        std::process::exit(1);
    }
    let key_path = args[0];
    let key = if key_path == "-" {
        Key::load(&mut std::io::stdin().lock())?
    } else {
        Key::load_from_file(key_path)?
    };
    std::fs::create_dir_all(get_internal_keys_path()?)?;
    key.store_to_file(get_internal_key_path()?)?;

    // 3. Install the key(s) and configure the git filters
    configure_git_filters()?;
    let encrypted_files: Vec<String> = get_encrypted_files()?;

    // 4. Check out the files that are currently encrypted.
    // Git won't check out a file if its mtime hasn't changed, so touch every file first.
    for path in &encrypted_files {
        touch_file(path)?;
    }
    if let Err(err) = git_checkout(&encrypted_files) {
        eprintln!("Error: 'git checkout' failed: {}", err);
        eprintln!(
            "git-rcrypt has been set up but existing encrypted files have not been decrypted"
        );
        std::process::exit(1);
    }
    Ok(())
}

fn help_lock(w: &mut dyn std::io::Write) {
    writeln!(w, "Usage: git-rcrypt lock [OPTIONS]",).unwrap();
}

fn lock(args: &[&str]) -> Result<(), Error> {
    if !args.is_empty() {
        eprintln!("parameters to lock command are not supported");
        std::process::exit(1);
    }

    // 1. Make sure working directory is clean (ignoring untracked files)
    // We do this because we check out files later, and we don't want the
    // user to lose any changes.

    // Running 'git status' also serves as a check that the Git repo is accessible.

    let git_status_output = get_git_status()?;
    if !git_status_output.is_empty() {
        eprintln!(
            "Error: Working directory not clean.
Please commit your changes or 'git stash' them before running 'git-rcrypt lock'."
        );
        std::process::exit(1);
    }

    // 2. deconfigure the git filters and remove decrypted keys
    let key_path = get_internal_key_path()?;
    if !is_file(&key_path) {
        eprintln!("Error: this repository is already locked");
        std::process::exit(1);
    }
    std::fs::remove_file(&key_path)?;
    deconfigure_git_filters()?;

    let encrypted_files = get_encrypted_files()?;

    // 3. Check out the files that are currently decrypted but should be encrypted.
    // Git won't check out a file if its mtime hasn't changed, so touch every file first.
    for path in &encrypted_files {
        touch_file(path)?;
    }
    if let Err(err) = git_checkout(&encrypted_files) {
        eprintln!("Error: 'git checkout' failed: {}", err);
        eprintln!(
            "git-rcrypt has been locked up but existing decrypted files have not been encrypted"
        );
        std::process::exit(1);
    }

    Ok(())
}

/// is_file checks if the given path is a file.
fn is_file(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}

/// touch_file updates access and modification of a file.
/// The file must exist.
fn touch_file(path: &str) -> std::io::Result<()> {
    let now = std::time::SystemTime::now();
    let now = ggstd::time::Time::from_systime(&now);
    ggstd::os::chtimes(path, &now, &now)
}

const HMAC_KEY_LEN: usize = 64;
const AES_KEY_LEN: usize = 32;

fn malformed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "This repository contains a malformed key file.  It may be corrupted.".to_string(),
    )
}

fn incompatible() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "This repository contains a incompatible key file.".to_string(),
    )
}

const KEY_FIELD_END: u32 = 0;
const KEY_FIELD_VERSION: u32 = 1;
const KEY_FIELD_AES_KEY: u32 = 3;
const KEY_FIELD_HMAC_KEY: u32 = 5;

const HEADER_FIELD_END: u32 = 0;
const HEADER_FIELD_KEY_NAME: u32 = 1;

const FORMAT_VERSION: u32 = 2;
const MAX_FIELD_LEN: u32 = 1 << 20;

const KEY_NAME_MAX_LEN: u32 = 128;

#[derive(Debug)]
struct Key {
    aes_key: [u8; AES_KEY_LEN],
    hmac_key: [u8; HMAC_KEY_LEN],
}

impl Key {
    fn generate() -> std::io::Result<Self> {
        let mut aes_key = [0; AES_KEY_LEN];
        let mut hmac_key = [0; HMAC_KEY_LEN];
        rand::read(&mut aes_key)?;
        rand::read(&mut hmac_key)?;
        Ok(Self { aes_key, hmac_key })
    }

    fn load(r: &mut dyn std::io::Read) -> std::io::Result<Self> {
        let mut preamble = [0_u8; 12];
        r.read_exact(&mut preamble)?;
        if &preamble != b"\0GITCRYPTKEY" {
            return Err(malformed());
        }
        if read_be32(r)? != FORMAT_VERSION {
            return Err(incompatible());
        }

        Self::load_header(r)?;

        let mut aes_key: Option<[u8; AES_KEY_LEN]> = None;
        let mut hmac_key: Option<[u8; HMAC_KEY_LEN]> = None;
        loop {
            let field_id = read_be32(r)?;
            if field_id == KEY_FIELD_END {
                break;
            }
            let field_len = read_be32(r)?;
            if field_id == KEY_FIELD_VERSION {
                if field_len != 4 {
                    return Err(malformed());
                }
                let version = read_be32(r)?;
                if version != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Key entry with version!=0 are not supported (version: {})",
                            version
                        ),
                    ));
                }
            } else if field_id == KEY_FIELD_AES_KEY {
                if field_len as usize != AES_KEY_LEN {
                    return Err(malformed());
                }
                let mut buf = [0; AES_KEY_LEN];
                r.read_exact(&mut buf)?;
                aes_key = Some(buf);
            } else if field_id == KEY_FIELD_HMAC_KEY {
                if field_len as usize != HMAC_KEY_LEN {
                    return Err(malformed());
                }
                let mut buf = [0; HMAC_KEY_LEN];
                r.read_exact(&mut buf)?;
                hmac_key = Some(buf);
            } else if field_id & 1 == 1 {
                // unknown critical field
                return Err(incompatible());
            } else {
                // unknown non-critical field - safe to ignore
                if field_len > MAX_FIELD_LEN {
                    return Err(malformed());
                }
                discard_exact(r, field_len as usize)?;
            }
        }

        if aes_key.is_none() || hmac_key.is_none() {
            return Err(malformed());
        }
        Ok(Self {
            aes_key: aes_key.unwrap(),
            hmac_key: hmac_key.unwrap(),
        })
    }

    fn store(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        w.write_all(b"\0GITCRYPTKEY")?;
        write_be32(w, FORMAT_VERSION)?;
        write_be32(w, HEADER_FIELD_END)?;
        self.store_entry(w)?;
        Ok(())
    }

    fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Self> {
        Key::load(&mut std::fs::File::open(path)?)
    }

    fn store_to_file<P: AsRef<std::path::Path>>(&self, key_file_path: P) -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::prelude::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(key_file_path)?;
        self.store(&mut file)?;
        file.flush()?;
        Ok(())
    }

    fn store_entry(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        write_be32(w, KEY_FIELD_VERSION)?;
        write_be32(w, 4)?;
        write_be32(w, 0)?;

        write_be32(w, KEY_FIELD_AES_KEY)?;
        write_be32(w, AES_KEY_LEN as u32)?;
        w.write_all(&self.aes_key)?;

        write_be32(w, KEY_FIELD_HMAC_KEY)?;
        write_be32(w, HMAC_KEY_LEN as u32)?;
        w.write_all(&self.hmac_key)?;

        write_be32(w, KEY_FIELD_END)?;
        Ok(())
    }

    fn load_header(r: &mut dyn std::io::Read) -> std::io::Result<()> {
        loop {
            let field_id = read_be32(r)?;
            if field_id == HEADER_FIELD_END {
                break;
            }
            let field_len = read_be32(r)?;
            if field_id == HEADER_FIELD_KEY_NAME {
                if field_len > KEY_NAME_MAX_LEN {
                    return Err(malformed());
                }
                // not loading the name
                discard_exact(r, field_len as usize)?;
            } else if field_id & 1 != 0 {
                // unknown critical field
                return Err(incompatible());
            } else {
                // unknown non-critical field - safe to ignore
                if field_len > MAX_FIELD_LEN {
                    return Err(malformed());
                }
                discard_exact(r, field_len as usize)?;
            }
        }
        Ok(())
    }
}

fn read_be32(r: &mut dyn std::io::Read) -> std::io::Result<u32> {
    let mut buf = [0; 4];
    r.read_exact(&mut buf)?;
    Ok(BIG_ENDIAN.uint32(&buf))
}

fn write_be32(w: &mut dyn std::io::Write, value: u32) -> std::io::Result<()> {
    let mut buf = [0; 4];
    BIG_ENDIAN.put_uint32(&mut buf, value);
    w.write_all(&buf)
}

fn escape_shell_arg(s: &str) -> String {
    let mut new_str = String::from("\"");
    for c in s.chars() {
        if c == '"' || c == '\\' || c == '$' || c == '`' {
            new_str.push('\\');
        }
        new_str.push(c);
    }
    new_str.push('"');
    new_str
}

/// Launch two processes and pipe output of the first process to the input of the second.
/// Return output of the second process.
fn launch_two_processes(cmd1: &[&str], cmd2: &[&str]) -> std::io::Result<std::process::Output> {
    let mut c1 = Command::new(cmd1[0])
        .args(&cmd1[1..])
        .stdout(Stdio::piped())
        .spawn()?;

    let stdout = c1.stdout.take().unwrap();

    let c2 = Command::new(cmd2[0])
        .args(&cmd2[1..])
        .stdin(stdout)
        .stdout(Stdio::piped())
        .spawn()?;

    c2.wait_with_output()
}

//  fn two_pipes_example() {
//     let output = launch_two_processes(
//         &[
//             "bash",
//             "-c",
//             "echo hello world; sleep 10; echo hello world 2",
//         ],
//         &["grep", "world"],
//     );
//     println!("{:?}", output);
// }

/// Launch a process and write given data to stdin of the process.
fn launch_and_write_to_stdin(
    cmd: &[&str],
    input_data: &[u8],
) -> std::io::Result<std::process::Output> {
    let mut child = Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .spawn()?;
    // let mut stdin = child.stdin.take().unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input_data)?;
    }
    // stdin.write_all(input_data)?;
    child.wait_with_output()
}

//  fn launch_and_write_to_stdin_example() {
//     let output = launch_and_write_to_stdin(&["wc"], b"hello");
//     println!("{:?}", output);
// }

/// discard_exact reads n bytes from the reader and discards them.
fn discard_exact(r: &mut dyn Read, n: usize) -> std::io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    let buf_size = n.min(64 * 1024);
    let mut buf = vec![0; buf_size];
    let mut n = n;
    while n > 0 {
        let size = n.min(buf_size);
        r.read_exact(&mut buf[0..size])?;
        n -= size;
    }
    Ok(())
}

/// Create and instance of std::io::Error with ErrorKind::Other.
fn new_other_err<E>(message: E) -> std::io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    std::io::Error::new(std::io::ErrorKind::Other, message)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_path_to_top() {
        assert_eq!(".", &get_path_to_top().unwrap());
    }

    fn decrypt_file(
        key: &Key,
        r: &mut dyn std::io::Read,
        w: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        let mut header = [0; ENCRYPTED_FILE_HEADER_SIZE];
        r.read_exact(&mut header)?;
        if &header[0..ENCRYPTED_FILE_MARKER_SIZE] != GITCRYPT_FILE_HEADER {
            return Err(new_other_err("invalid header".to_string()));
        }
        decrypt_file_after_header(
            key,
            &header[ENCRYPTED_FILE_MARKER_SIZE..ENCRYPTED_FILE_HEADER_SIZE],
            r,
            w,
        )
    }

    #[test]
    fn test_decrypt_file() {
        let key = Key::load_from_file("testdata/01/key.bin").unwrap();
        let mut f = std::fs::File::open("testdata/01/hello.txt_encrypted").unwrap();
        let mut w = std::io::Cursor::new(Vec::new());
        decrypt_file(&key, &mut f, &mut w).unwrap();
        let want = std::fs::read("testdata/01/hello.txt_decrypted").unwrap();
        assert_eq!(&want, w.get_ref());
    }

    #[test]
    fn test_encrypt_file() {
        let key = Key::load_from_file("testdata/01/key.bin").unwrap();
        let mut f = std::fs::File::open("testdata/01/hello.txt_decrypted").unwrap();
        let mut w = std::io::Cursor::new(Vec::new());
        encrypt_file(&key, &mut f, &mut w).unwrap();
        let want = std::fs::read("testdata/01/hello.txt_encrypted").unwrap();
        assert_eq!(&want, w.get_ref());
    }

    #[test]
    fn test_key_load() {
        let mut f = std::fs::File::open("testdata/01/key.bin").unwrap();
        let _k = Key::load(&mut f).unwrap();
    }

    #[test]
    fn test_discard_exact() {
        // reading a small buffer
        {
            let mut r = std::io::BufReader::new(&b"0123456789abcdef"[..]);
            discard_exact(&mut r, 0).unwrap();
            discard_exact(&mut r, 10).unwrap();
            let mut buf = [0; 1];
            r.read_exact(&mut buf[0..1]).unwrap();
            assert_eq!(buf[0], b'a');
            assert_eq!(
                discard_exact(&mut r, 10).err().unwrap().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }

        // big buffer
        {
            let mut read_buf = vec![0_u8; 1024 * 1024];
            read_buf[512 * 1024] = 55;
            let mut r = std::io::BufReader::new(&read_buf[..]);
            discard_exact(&mut r, 512 * 1024 - 1).unwrap();
            let mut buf = [0; 10];
            r.read_exact(&mut buf).unwrap();
            assert_eq!(buf[1], 55);
        }
    }
}
