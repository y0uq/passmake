# passmake

`passmake` is a tiny Linux command line password generator written in C. It
prints a cryptographically secure alphanumeric password using uppercase letters,
lowercase letters, and numbers.

The normal generation path writes only the password to stdout. Warnings and
errors go to stderr. Help, version, and security text are printed only when
explicitly requested.

## Build

```sh
make
```

That creates `./passmake`.

Run a small built-in smoke check:

```sh
make check
```

Remove the executable:

```sh
make clean
```

Install the binary:

```sh
sudo make install
```

Install somewhere else:

```sh
make PREFIX="$HOME/.local" install
```

## Usage

Generate the default 24-character password:

```sh
./passmake
```

Generate a specific length:

```sh
./passmake 24
./passmake 32
```

Use named length options if desired:

```sh
./passmake --length 24
./passmake --length=24
```

`--count` is accepted as a compatibility alias:

```sh
./passmake --count 24
./passmake --count=24
```

Suppress the default trailing newline:

```sh
./passmake 24 --no-newline
```

This is useful when piping into clipboard tools:

```sh
./passmake 24 --no-newline | your-clipboard-command
```

Show help, version, or the security explanation:

```sh
./passmake --help
./passmake --version
./passmake --security
```

Arguments after `--` are treated as positional values:

```sh
./passmake -- 24
```

## Lengths

- Default length: 24 characters.
- Recommended website password length: 24 or more characters.
- Valid range: 3 to 4096 characters.
- Lengths below 12 are allowed but warn to stderr unless `--quiet` is used.
- The minimum length is mechanical, not recommended. It exists only because the
  program enforces at least one uppercase letter, one lowercase letter, and one
  digit.

## Security

- Randomness comes from Linux `getrandom(2)`.
- `/dev/urandom` is used only as a compatibility fallback if `getrandom(2)` is
  unavailable.
- The alphabet is intentionally alphanumeric: `A-Z`, `a-z`, and `0-9`.
- Rejection sampling avoids modulo bias when mapping random bytes to characters.
- Whole-password rejection keeps output uniform over the subset of alphanumeric
  strings that satisfy the uppercase, lowercase, and digit requirement.
- Password output uses unbuffered descriptor writes to avoid libc-managed stdout
  buffers holding password material.
- Random-byte and password buffers are cleared before exit to reduce residual
  exposure. This is a hardening measure, not an absolute guarantee.
- Core dumps are disabled during password generation where supported.

Printing to a terminal can leave the password visible in terminal scrollback.
`passmake` does not put generated passwords in shell history by itself, but
command substitution, environment variables, or manual handling can expose them.
Avoid storing generated passwords in environment variables, and store generated
passwords in a password manager.

## Exit Status

- `0`: success
- `2`: usage or argument error
- `3`: randomness or generation failure
- `4`: memory allocation failure
- `5`: stdout write failure
