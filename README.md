# git-rcrypt

`git-rcrypt` is a simplified version of [git-crypt](https://github.com/AGWA/git-crypt).

## How to install

- install Rust: https://www.rust-lang.org/tools/install.
- install `git-rcrypt`:

```
cargo install --git https://github.com/gtrafimenkov/git-rcrypt --tag v0.0.1
```

## How to use with an existing git-rcrypt repository

Install `git-rcrypt`.

Get the key for the repository:
- open the repository with `git-rcrypt unlock`
- copy `.git/git-rcrypt/keys/default` to a secure place; this is the key for opening the repository
- lock the repository with `git-rcrypt lock`

Unlock the repository using the key:
- `git-rcrypt unlock PATH_TO_THE_KEY`

## How to use with a new repository

- install `git-rcrypt`
- `git-rcrypt init`
- copy `.git/git-rcrypt/keys/default` to a secure place; this is the key for opening the repository
- create file `.gitattributes` similar to this one [.gitattributes](/.gitattributes)

## Not supported git-crypt features

Not supported:
- multiple keys
- multiple key entries per key
- key names
- GPG
- `status` command

## License

GPL v3 or later
