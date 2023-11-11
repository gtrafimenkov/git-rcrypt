// Copyright 2023 git-rcrypt developers
// Copyright 2012, 2014 Andrew Ayer
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Error;
use std::io::Write;

use ggstd::crypto::aes;
use ggstd::crypto::cipher::{self, Stream};
use ggstd::crypto::hmac::HMAC;
use ggstd::crypto::rand;
use ggstd::crypto::sha256;
use ggstd::hash::Hash;
use std::process::{Command, Stdio};

const VERSION: &str = "0.0.2";

fn print_usage(program_name: &str, out: &mut dyn std::io::Write) {
    writeln!(
        out,
        r#"Usage: {} COMMAND [ARGS ...]

Commands:
  init             Initialize the git repository to use encryption.
  lock             Deconfigure git-rcrypt and reencrypt unlocked files in the work tree.
  unlock KEYFILE   Decrypt this repo using the key from KEYFILE.
                   If KEYFILE is "-", the key will be read from the standard input.

"#,
        program_name
    )
    .unwrap();
}

fn print_version(out: &mut dyn std::io::Write) {
    writeln!(out, "git-rcrypt {}", VERSION).unwrap();
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
        "help" => {
            print_usage(program_name, &mut std::io::stdout());
            Ok(())
        }
        "version" => {
            print_version(&mut std::io::stdout());
            Ok(())
        }
        "init" => init(),
        "unlock" => unlock(args),
        "lock" => lock(),
        "clean" => clean(),
        "smudge" => smudge(),
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

const ENC_FILE_MARKER_SIZE: usize = 8;
const ENC_FILE_MARKER: &[u8; ENC_FILE_MARKER_SIZE] = b"GRCRPT\x00\x01";
const AES_KEY_SIZE: usize = 32; // AES-256
const HMAC_SIZE: usize = 32; //sha256 HMAC
const ENC_FILE_HEADER_SIZE: usize = ENC_FILE_MARKER_SIZE + HMAC_SIZE;

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

/// Return path to the .git directory of the current git repository.
fn get_repo_root() -> std::io::Result<String> {
    let output = exec_git_for_output(
        &["rev-parse", "--git-dir"],
        true,
        "'git rev-parse --git-dir' failed - is this a Git repository?",
    )?;
    if output.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            ".git directory is not found",
        ));
    }
    Ok(output)
}

fn get_key_path() -> std::io::Result<String> {
    Ok(format!("{}/git-rcrypt.key", get_repo_root()?))
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
    let key_path = std::path::PathBuf::from(get_key_path()?);
    let mut f = std::fs::File::open(key_path)?;
    Key::load(&mut f)
}

fn encrypt_file(
    key: &Key,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    // read the entire file into memory
    let mut data = Vec::with_capacity(4 * 1024 * 1024);
    r.read_to_end(&mut data)?;

    // calculate hmac
    let mut hmac = HMAC::new(sha256::Digest::new, &key.key);
    hmac.write_all(&data).unwrap();
    let digest = hmac.sum(&[]);

    // write header
    w.write_all(ENC_FILE_MARKER)?; // ...identifies this as an encrypted file
    w.write_all(&digest[..HMAC_SIZE])?; // ...includes the nonce

    // encrypt the file
    let iv = &digest[..aes::BLOCK_SIZE];
    let block = aes::Cipher::new(&key.key).unwrap();
    let mut stream = cipher::CTR::new(&block, iv);
    stream.xor_key_stream_inplace(&mut data);
    w.write_all(&data)?;
    w.flush()?;
    Ok(())
}

/// Encrypt contents of stdin and write to stdout
fn clean() -> Result<(), Error> {
    encrypt_file(
        &load_key()?,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )
}

/// Decrypt file and return true if the file was encrypted before.
fn decrypt_file(
    key: &Key,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> std::io::Result<bool> {
    let mut header = [0; ENC_FILE_HEADER_SIZE];
    let n = r.read(&mut header)?;
    if n != ENC_FILE_HEADER_SIZE || &header[..ENC_FILE_MARKER_SIZE] != ENC_FILE_MARKER {
        w.write_all(&header[..n])?;
        std::io::copy(r, w)?;
        Ok(false)
    } else {
        decrypt_file_after_header(
            key,
            &header[ENC_FILE_MARKER_SIZE..ENC_FILE_HEADER_SIZE],
            r,
            w,
        )?;
        Ok(true)
    }
}

fn decrypt_file_after_header(
    key: &Key,
    digest: &[u8],
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let iv = &digest[..aes::BLOCK_SIZE];
    let block = aes::Cipher::new(&key.key).unwrap();
    let mut stream = cipher::CTR::new(&block, iv);
    let mut hmac = HMAC::new(sha256::Digest::new, &key.key);
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

    let new_digest = hmac.sum(&[]);
    if new_digest[..HMAC_SIZE] != digest[..HMAC_SIZE] {
        return Err(new_other_err(
            "decrypted file checksum doesn't match".to_string(),
        ));
    }
    Ok(())
}

/// Decrypt contents of stdin and write to stdout
fn smudge() -> Result<(), Error> {
    if !decrypt_file(
        &load_key()?,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
    )? {
        eprintln!("git-rcrypt: Warning: file is not encrypted.");
    }
    Ok(())
}

fn diff(args: &[&str]) -> Result<(), Error> {
    if args.len() != 1 {
        eprintln!("parameters to diff command are not supported");
        std::process::exit(1);
    }
    if !decrypt_file(
        &load_key()?,
        &mut std::fs::File::open(args[0])?,
        &mut std::io::stdout().lock(),
    )? {
        eprintln!("git-rcrypt: Warning: file is not encrypted.");
    }
    Ok(())
}

fn init() -> Result<(), Error> {
    let key_path = get_key_path()?;
    if is_file(&key_path) {
        eprintln!("Error: this repository has already been initialized with git-rcrypt.");
        std::process::exit(1);
    }

    let key = Key::generate()?;
    key.store_to_file(key_path)?;
    configure_git_filters()?;

    eprintln!(
        r#"The repository was initialized.
Next:
1) copy ".git/git-rcrypt.key" to a secure place
2) create .gitattributes to tell git what files should be encrypted
"#
    );
    Ok(())
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
    key.store_to_file(get_key_path()?)?;

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

fn lock() -> Result<(), Error> {
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
    let key_path = get_key_path()?;
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

#[derive(Debug)]
struct Key {
    key: [u8; AES_KEY_SIZE],
}

impl Key {
    fn generate() -> std::io::Result<Self> {
        let mut aes_key = [0; AES_KEY_SIZE];
        rand::read(&mut aes_key)?;
        Ok(Self { key: aes_key })
    }

    fn load(r: &mut dyn std::io::Read) -> std::io::Result<Self> {
        let mut aes_key = [0; AES_KEY_SIZE];
        r.read_exact(&mut aes_key)?;
        Ok(Self { key: aes_key })
    }

    fn store(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        w.write_all(&self.key)
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

    #[test]
    fn test_decrypt_file() {
        let key = Key::load_from_file("testdata/02/key.bin").unwrap();
        let mut f = std::fs::File::open("testdata/02/hello.txt_encrypted").unwrap();
        let mut w = std::io::Cursor::new(Vec::new());
        decrypt_file(&key, &mut f, &mut w).unwrap();
        let want = std::fs::read("testdata/02/hello.txt_decrypted").unwrap();
        assert_eq!(&want, w.get_ref());
    }

    #[test]
    fn test_encrypt_file() {
        let key = Key::load_from_file("testdata/02/key.bin").unwrap();
        let mut f = std::fs::File::open("testdata/02/hello.txt_decrypted").unwrap();
        let mut w = std::io::Cursor::new(Vec::new());
        encrypt_file(&key, &mut f, &mut w).unwrap();
        let want = std::fs::read("testdata/02/hello.txt_encrypted").unwrap();
        assert_eq!(&want, w.get_ref());
    }

    #[test]
    fn test_key_load() {
        let mut f = std::fs::File::open("testdata/02/key.bin").unwrap();
        let _k = Key::load(&mut f).unwrap();
    }
}
