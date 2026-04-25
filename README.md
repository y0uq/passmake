# passmake

`passmake` is a small Linux command line password generator written in C.
It prints a cryptographically secure password made from uppercase letters,
lowercase letters, and numbers.

Successful password generation writes only the generated password to standard
output. Errors and help text are separate from normal password output.

## Build

`passmake` builds with a standard C compiler and `make`.

On Debian or Ubuntu, install the build tools if needed:

```sh
sudo apt install build-essential
```

On Fedora:

```sh
sudo dnf install make gcc
```

Build the executable:

```sh
make
```

This creates the `passmake` executable:

```sh
./passmake 32
```

You can also compile it directly without `make`:

```sh
cc -std=c11 -O2 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes -o passmake main.c
```

To confirm the build works:

```sh
./passmake 32
./passmake --help
./passmake --security
```

Remove the built executable:

```sh
make clean
```

## Usage

The simplest and preferred form is positional:

```sh
./passmake COUNT
```

Examples:

```sh
./passmake 16
./passmake 32
./passmake 64
```

Optional long-form arguments are also supported:

```sh
./passmake --length 32
./passmake --length=32
./passmake --count 32
./passmake --count=32
```

Suppress the trailing newline when embedding the password in another command:

```sh
./passmake 32 --no-newline
```

Show help:

```sh
./passmake --help
```

Explain the program's cryptographic security design:

```sh
./passmake --security
```

## Password Rules

- Length must be between 3 and 4096 characters.
- Characters are limited to `A-Z`, `a-z`, and `0-9`.
- Every generated password contains at least one uppercase letter, one lowercase
  letter, and one digit.

## Security Notes

- Random bytes come from Linux `getrandom(2)`, with `/dev/urandom` used only as
  a compatibility fallback if `getrandom` is unavailable.
- Character selection uses rejection sampling to avoid modulo bias.
- Passwords are generated uniformly from the accepted password set instead of
  forcing required character classes into fixed positions.
- Temporary password and random-byte buffers are cleared before the program
  exits.
