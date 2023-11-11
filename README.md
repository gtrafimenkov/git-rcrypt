# git-rcrypt

`git-rcrypt` encrypts files in a git repository.  It is similar to [git-crypt](https://github.com/AGWA/git-crypt), but not compatible.

Goals of the project:
- easy installation on Windows
- to be a small and simple program

## How to install

- install Rust: https://www.rust-lang.org/tools/install
- install `git-rcrypt`:

```
cargo install --git https://github.com/gtrafimenkov/git-rcrypt --tag v0.0.2
```

## How to use

- initialize encryption in a git repository: `git-rcrypt init`
- **important**: copy `.git/git-rcrypt.key` to a secure place; this is the key for unlocking (decrypting) the repository
- create file `.gitattributes` similar to this one [.gitattributes](/.gitattributes); it will tell Git what
  files should be encrypted

## How encryption works

- `git-rcrypt` uses [git smudge and clean filters](https://git-scm.com/book/en/v2/Customizing-Git-Git-Attributes)
  functionality to encrypt files on commit and decrypt on checkout
- `git-rcrypt init` generates a new encryption key, stores it to `.git/git-rcrypt.key`, configures `git-rcrypt`
  as a clean, smudge and diff filter
- after that files configured for encryption in `.gitattributes` will be automatically encrypted and decrypted
- `git-rcrypt lock` deconfigures `git-rcrypt` as the filter, removes the key file, checks out encrypted files.
  After that, decrypted checked out files will be replaced with their encrypted variants
- `git-rcrypt unlock` takes a path to the key file, copies it to `.git/git-rcrypt.key`, configures itself
  as a clean, smudge, diff filter and checks out encrypted files.  The files will be decrypted during checkout

## Encryption details

- files are encrypted with AES in CTR mode using 256 bit key
- encrypted files are authenticated using HMAC sha256
- HMAC sha256 of an unencrypted file is used as the initialization vector for encryption

## Storing the key

- store the key file in a secure place
- alternatively, encode it into base64 and store in a password manager:
  - encoding the key: `cat .git/git-rcrypt.key | base64`
  - unlocking repository with encoded key: `base64 -d | git-rcrypt unlock -`

## License

GPL v3 or later
