#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <unistd.h>

#define PASSMAKE_VERSION "1.0.0"

enum {
    MIN_PASSWORD_LENGTH = 3,
    DEFAULT_PASSWORD_LENGTH = 24,
    RECOMMENDED_PASSWORD_LENGTH = 24,
    SHORT_PASSWORD_WARNING_LENGTH = 12,
    MAX_PASSWORD_LENGTH = 4096,
    RANDOM_POOL_SIZE = 4096,
    MAX_GENERATION_ATTEMPTS = 100000
};

typedef enum {
    PASSMAKE_OK = 0,
    PASSMAKE_USAGE = 2,
    PASSMAKE_RANDOM_FAILURE = 3,
    PASSMAKE_ALLOCATION_FAILURE = 4,
    PASSMAKE_OUTPUT_FAILURE = 5
} PassmakeExit;

typedef enum {
    LENGTH_PARSE_OK,
    LENGTH_PARSE_EMPTY,
    LENGTH_PARSE_NEGATIVE,
    LENGTH_PARSE_SIGNED,
    LENGTH_PARSE_NOT_DECIMAL,
    LENGTH_PARSE_TOO_SMALL,
    LENGTH_PARSE_TOO_LARGE
} LengthParseResult;

typedef enum {
    GENERATE_OK,
    GENERATE_RANDOM_ERROR,
    GENERATE_RETRY_LIMIT
} GenerateResult;

typedef enum {
    WRITE_OK,
    WRITE_ERROR
} WriteResult;

typedef enum {
    REQUEST_GENERATE,
    REQUEST_HELP,
    REQUEST_SECURITY,
    REQUEST_VERSION
} RequestMode;

static const char ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789";

static const size_t ALPHABET_LENGTH = sizeof(ALPHABET) - 1U;

typedef struct {
    size_t length;
    bool length_set;
    bool quiet;
    bool trailing_newline;
} Options;

typedef struct {
    unsigned char bytes[RANDOM_POOL_SIZE];
    size_t offset;
    size_t available;
} RandomPool;

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');

    if (slash == NULL) {
        return path;
    }

    return slash + 1;
}

static void secure_zero(void *ptr, size_t len)
{
    if (ptr == NULL || len == 0U) {
        return;
    }

#if defined(__GLIBC__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len > 0U) {
        *p = 0U;
        ++p;
        --len;
    }
#endif
}

static void print_help(const char *program)
{
    printf("Usage:\n");
    printf("  %s [LENGTH] [--no-newline] [--quiet]\n", program);
    printf("  %s [--length LENGTH] [--no-newline] [--quiet]\n", program);
    printf("  %s --help | --security | --version\n", program);
    printf("\n");
    printf("Generate a cryptographically secure password using only A-Z, a-z, and 0-9.\n");
    printf("Generated passwords always contain at least one uppercase letter, one lowercase\n");
    printf("letter, and one digit.\n");
    printf("With no LENGTH, the default is %d characters.\n", DEFAULT_PASSWORD_LENGTH);
    printf("Recommended website password length: %d or more characters.\n",
           RECOMMENDED_PASSWORD_LENGTH);
    printf("Valid length range: %d-%d characters. The minimum is mechanical, not\n",
           MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
    printf("recommended; it exists only because uppercase, lowercase, and digit presence\n");
    printf("are enforced.\n");
    printf("\n");
    printf("Options:\n");
    printf("  --length LENGTH      Optional named form for positional LENGTH (%d-%d).\n",
           MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
    printf("  --length=LENGTH     Same as --length LENGTH.\n");
    printf("  --count LENGTH       Compatibility alias for --length LENGTH.\n");
    printf("  --count=LENGTH      Compatibility alias for --length=LENGTH.\n");
    printf("  --no-newline         Do not append the default trailing newline.\n");
    printf("  --quiet              Suppress non-error warnings, such as short length.\n");
    printf("  --security           Explain the program's cryptographic security design.\n");
    printf("  --version            Print version information and exit.\n");
    printf("  --                   Treat the following argument as positional LENGTH.\n");
    printf("  --help               Show this help text and exit.\n");
}

static void print_security(void)
{
    printf("passmake %s cryptographic security design:\n", PASSMAKE_VERSION);
    printf("\n");
    printf("- Randomness comes from the Linux kernel CSPRNG through getrandom(2).\n");
    printf("- If getrandom(2) is unavailable, /dev/urandom is used as a compatibility\n");
    printf("  fallback.\n");
    printf("- Password characters are chosen from 62 symbols: A-Z, a-z, and 0-9.\n");
    printf("  Alphanumeric-only output is intentional for restrictive signup forms; it is\n");
    printf("  not the maximum possible entropy density for a password of this length.\n");
    printf("- Rejection sampling is used when mapping random bytes to characters, so\n");
    printf("  character selection does not suffer from modulo bias.\n");
    printf("- The whole password is regenerated until it contains at least one uppercase\n");
    printf("  letter, one lowercase letter, and one digit. This keeps accepted passwords\n");
    printf("  uniformly distributed across the subset of alphanumeric strings satisfying\n");
    printf("  the class requirement, instead of forcing fixed positions for classes.\n");
    printf("- Length and randomness provide the real security. Character classes improve\n");
    printf("  compatibility with password forms; they do not make short passwords strong.\n");
    printf("- A uniformly random alphanumeric character carries about 5.95 bits before\n");
    printf("  the required-class conditioning. Examples: 12 characters is about 71 bits,\n");
    printf("  24 is about 143 bits, and 32 is about 190 bits before that small adjustment.\n");
    printf("- Random-byte buffers and the generated password buffer are cleared before\n");
    printf("  exit to reduce leftover sensitive data in process memory. This reduces\n");
    printf("  residual exposure but cannot guarantee removal from every OS, terminal, or\n");
    printf("  hardware location.\n");
    printf("\n");
    printf("Operational limits:\n");
    printf("- Printing to a terminal can leave the password visible in terminal scrollback.\n");
    printf("- The generated password is not placed in shell history by passmake itself,\n");
    printf("  but command substitution, environment variables, or manual handling can\n");
    printf("  expose it. Avoid storing generated passwords in environment variables.\n");
    printf("- Store generated passwords in a password manager.\n");
    printf("- Threat model: passmake protects against predictable password generation. It\n");
    printf("  does not protect against compromised terminals, malware, exposed clipboards,\n");
    printf("  weak websites, or unsafe storage after generation.\n");
}

static void print_version(void)
{
    printf("passmake %s\n", PASSMAKE_VERSION);
}

static bool ascii_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static LengthParseResult parse_length(const char *text, size_t *length)
{
    unsigned long parsed = 0UL;
    const char *cursor = text;

    if (text == NULL || text[0] == '\0') {
        return LENGTH_PARSE_EMPTY;
    }

    if (text[0] == '-') {
        if (ascii_is_digit(text[1]) || text[1] == '.' || text[1] == '\0') {
            return LENGTH_PARSE_NEGATIVE;
        }
        return LENGTH_PARSE_NOT_DECIMAL;
    }

    if (text[0] == '+') {
        return LENGTH_PARSE_SIGNED;
    }

    while (*cursor != '\0') {
        if (!ascii_is_digit(*cursor)) {
            return LENGTH_PARSE_NOT_DECIMAL;
        }
        ++cursor;
    }

    errno = 0;
    parsed = strtoul(text, NULL, 10);
    if (errno == ERANGE) {
        return LENGTH_PARSE_TOO_LARGE;
    }

    if (parsed < (unsigned long)MIN_PASSWORD_LENGTH) {
        return LENGTH_PARSE_TOO_SMALL;
    }

    if (parsed > (unsigned long)MAX_PASSWORD_LENGTH) {
        return LENGTH_PARSE_TOO_LARGE;
    }

    *length = (size_t)parsed;
    return LENGTH_PARSE_OK;
}

static void describe_length_error(const char *source, const char *value, LengthParseResult result,
                                  char *message, size_t message_size)
{
    switch (result) {
    case LENGTH_PARSE_EMPTY:
        (void)snprintf(message, message_size, "%s: empty length value", source);
        break;
    case LENGTH_PARSE_NEGATIVE:
        (void)snprintf(message, message_size, "%s: negative lengths are invalid: %s", source,
                       value);
        break;
    case LENGTH_PARSE_SIGNED:
        (void)snprintf(message, message_size, "%s: signed lengths are invalid: %s", source,
                       value);
        break;
    case LENGTH_PARSE_NOT_DECIMAL:
        (void)snprintf(message, message_size, "%s: length must be decimal digits: %s", source,
                       value);
        break;
    case LENGTH_PARSE_TOO_SMALL:
        (void)snprintf(message, message_size,
                       "%s: length %s is below the mechanical minimum of %d", source, value,
                       MIN_PASSWORD_LENGTH);
        break;
    case LENGTH_PARSE_TOO_LARGE:
        (void)snprintf(message, message_size, "%s: length %s exceeds the maximum of %d", source,
                       value, MAX_PASSWORD_LENGTH);
        break;
    case LENGTH_PARSE_OK:
        (void)snprintf(message, message_size, "%s: invalid length: %s", source, value);
        break;
    }
}

static bool set_length_once(Options *options, const char *value, const char *source, char *message,
                            size_t message_size)
{
    size_t parsed = 0U;
    const LengthParseResult result = parse_length(value, &parsed);

    if (options->length_set) {
        (void)snprintf(message, message_size, "%s: multiple length values are not allowed",
                       source);
        return false;
    }

    if (result != LENGTH_PARSE_OK) {
        describe_length_error(source, value, result, message, message_size);
        return false;
    }

    options->length = parsed;
    options->length_set = true;
    return true;
}

static bool looks_like_negative_length(const char *arg)
{
    return arg[0] == '-' && (ascii_is_digit(arg[1]) || arg[1] == '.' || arg[1] == '\0');
}

static bool option_value(const char *arg, const char *name, const char **value)
{
    const size_t name_len = strlen(name);

    if (strncmp(arg, name, name_len) != 0) {
        return false;
    }

    if (arg[name_len] != '=') {
        return false;
    }

    *value = arg + name_len + 1U;
    return true;
}

static bool parse_args(int argc, char **argv, Options *options, RequestMode *mode, char *message,
                       size_t message_size)
{
    bool parse_options = true;

    options->length = 0U;
    options->length_set = false;
    options->quiet = false;
    options->trailing_newline = true;
    *mode = REQUEST_GENERATE;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        const char *value = NULL;

        if (parse_options && strcmp(arg, "--help") == 0) {
            *mode = REQUEST_HELP;
            return true;
        }

        if (parse_options && strcmp(arg, "--security") == 0) {
            *mode = REQUEST_SECURITY;
            return true;
        }

        if (parse_options && strcmp(arg, "--version") == 0) {
            *mode = REQUEST_VERSION;
            return true;
        }

        if (parse_options && strcmp(arg, "--") == 0) {
            parse_options = false;
            continue;
        }

        if (parse_options && strcmp(arg, "--quiet") == 0) {
            options->quiet = true;
            continue;
        }

        if (parse_options && strcmp(arg, "--no-newline") == 0) {
            options->trailing_newline = false;
            continue;
        }

        if (parse_options && (strcmp(arg, "--length") == 0 || strcmp(arg, "--count") == 0)) {
            if (i + 1 >= argc) {
                (void)snprintf(message, message_size, "%s: missing length value", arg);
                return false;
            }

            ++i;
            if (!set_length_once(options, argv[i], arg, message, message_size)) {
                return false;
            }
            continue;
        }

        if (parse_options && (option_value(arg, "--length", &value)
                              || option_value(arg, "--count", &value))) {
            if (!set_length_once(options, value, arg, message, message_size)) {
                return false;
            }
            continue;
        }

        if (parse_options && strncmp(arg, "--", 2U) == 0) {
            (void)snprintf(message, message_size, "unknown option: %s", arg);
            return false;
        }

        if (parse_options && arg[0] == '-' && arg[1] != '\0'
            && !looks_like_negative_length(arg)) {
            (void)snprintf(message, message_size, "unknown option: %s", arg);
            return false;
        }

        if (!set_length_once(options, arg, "positional length", message, message_size)) {
            return false;
        }
    }

    if (!options->length_set) {
        options->length = DEFAULT_PASSWORD_LENGTH;
        options->length_set = true;
    }

    return true;
}

static int fill_from_urandom(unsigned char *buffer, size_t length)
{
    int fd = -1;

    do {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    } while (fd == -1 && errno == EINTR);

    if (fd == -1) {
        return -1;
    }

    while (length > 0U) {
        const ssize_t got = read(fd, buffer, length);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)close(fd);
            return -1;
        }

        if (got == 0) {
            errno = EIO;
            (void)close(fd);
            return -1;
        }

        buffer += (size_t)got;
        length -= (size_t)got;
    }

    if (close(fd) != 0) {
        return -1;
    }

    return 0;
}

static int fill_random(unsigned char *buffer, size_t length)
{
    while (length > 0U) {
        const ssize_t got = getrandom(buffer, length, 0U);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == ENOSYS) {
                return fill_from_urandom(buffer, length);
            }

            return -1;
        }

        if (got == 0) {
            errno = EIO;
            return -1;
        }

        buffer += (size_t)got;
        length -= (size_t)got;
    }

    return 0;
}

static void random_pool_init(RandomPool *pool)
{
    pool->offset = 0U;
    pool->available = 0U;
}

static int random_pool_byte(RandomPool *pool, unsigned char *byte)
{
    if (pool->offset == pool->available) {
        if (fill_random(pool->bytes, sizeof(pool->bytes)) != 0) {
            return -1;
        }

        pool->offset = 0U;
        pool->available = sizeof(pool->bytes);
    }

    *byte = pool->bytes[pool->offset];
    ++pool->offset;
    return 0;
}

static bool byte_to_alphabet_index(unsigned char byte, size_t *index)
{
    const unsigned int bucket_size = 256U;
    const unsigned int limit = bucket_size - (bucket_size % (unsigned int)ALPHABET_LENGTH);

    if ((unsigned int)byte >= limit) {
        return false;
    }

    *index = (size_t)((unsigned int)byte % (unsigned int)ALPHABET_LENGTH);
    return true;
}

static int random_alphabet_index(RandomPool *pool, size_t *index)
{
    for (;;) {
        unsigned char byte = 0U;

        if (random_pool_byte(pool, &byte) != 0) {
            return -1;
        }

        if (byte_to_alphabet_index(byte, index)) {
            return 0;
        }
    }
}

static void classify_char(char c, bool *has_upper, bool *has_lower, bool *has_digit)
{
    if (c >= 'A' && c <= 'Z') {
        *has_upper = true;
    } else if (c >= 'a' && c <= 'z') {
        *has_lower = true;
    } else if (c >= '0' && c <= '9') {
        *has_digit = true;
    }
}

static GenerateResult generate_password(char *password, size_t length)
{
    RandomPool pool;

    random_pool_init(&pool);

    /*
     * Regenerate complete candidates instead of injecting required classes into
     * selected positions. Conditioning full uniform samples preserves uniformity
     * over the accepted subset of alphanumeric strings.
     */
    for (size_t attempt = 0U; attempt < (size_t)MAX_GENERATION_ATTEMPTS; ++attempt) {
        bool has_upper = false;
        bool has_lower = false;
        bool has_digit = false;

        for (size_t i = 0U; i < length; ++i) {
            size_t index = 0U;

            if (random_alphabet_index(&pool, &index) != 0) {
                secure_zero(&pool, sizeof(pool));
                return GENERATE_RANDOM_ERROR;
            }

            password[i] = ALPHABET[index];
            classify_char(password[i], &has_upper, &has_lower, &has_digit);
        }

        if (has_upper && has_lower && has_digit) {
            password[length] = '\0';
            secure_zero(&pool, sizeof(pool));
            return GENERATE_OK;
        }
    }

    secure_zero(&pool, sizeof(pool));
    return GENERATE_RETRY_LIMIT;
}

static WriteResult write_all(int fd, const char *buffer, size_t length)
{
    while (length > 0U) {
        const ssize_t written = write(fd, buffer, length);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return WRITE_ERROR;
        }

        if (written == 0) {
            errno = EIO;
            return WRITE_ERROR;
        }

        buffer += (size_t)written;
        length -= (size_t)written;
    }

    return WRITE_OK;
}

static WriteResult write_password(const char *password, size_t length, bool trailing_newline)
{
    const char newline = '\n';

    if (write_all(STDOUT_FILENO, password, length) != WRITE_OK) {
        return WRITE_ERROR;
    }

    if (trailing_newline && write_all(STDOUT_FILENO, &newline, 1U) != WRITE_OK) {
        return WRITE_ERROR;
    }

    return WRITE_OK;
}

static void harden_process_for_secret_generation(void)
{
    const struct rlimit no_core = {0, 0};

    (void)setrlimit(RLIMIT_CORE, &no_core);

#if defined(PR_SET_DUMPABLE)
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

static void warn_if_short_password(const char *program, const Options *options)
{
    if (options->quiet || options->length >= (size_t)SHORT_PASSWORD_WARNING_LENGTH) {
        return;
    }

    fprintf(stderr,
            "%s: warning: length %zu is valid but short; %d+ characters are recommended "
            "for website passwords (use --quiet to suppress this warning)\n",
            program, options->length, RECOMMENDED_PASSWORD_LENGTH);
}

int main(int argc, char **argv)
{
    Options options;
    RequestMode mode = REQUEST_GENERATE;
    GenerateResult generate_result = GENERATE_OK;
    char message[128];
    char *password = NULL;
    const char *program = (argc > 0 && argv[0] != NULL) ? base_name(argv[0]) : "passmake";

    message[0] = '\0';

    if (!parse_args(argc, argv, &options, &mode, message, sizeof(message))) {
        fprintf(stderr, "%s: %s\n", program, message);
        fprintf(stderr, "Try '%s --help' for usage.\n", program);
        return PASSMAKE_USAGE;
    }

    if (mode == REQUEST_HELP) {
        print_help(program);
        return PASSMAKE_OK;
    }

    if (mode == REQUEST_SECURITY) {
        print_security();
        return PASSMAKE_OK;
    }

    if (mode == REQUEST_VERSION) {
        print_version();
        return PASSMAKE_OK;
    }

    warn_if_short_password(program, &options);
    harden_process_for_secret_generation();
    (void)signal(SIGPIPE, SIG_IGN);

    password = malloc(options.length + 1U);
    if (password == NULL) {
        fprintf(stderr, "%s: memory allocation failed\n", program);
        return PASSMAKE_ALLOCATION_FAILURE;
    }

    generate_result = generate_password(password, options.length);
    if (generate_result != GENERATE_OK) {
        if (generate_result == GENERATE_RANDOM_ERROR) {
            fprintf(stderr, "%s: failed to read secure random bytes\n", program);
        } else {
            fprintf(stderr, "%s: failed to generate a valid password after retry limit\n",
                    program);
        }
        secure_zero(password, options.length + 1U);
        free(password);
        return PASSMAKE_RANDOM_FAILURE;
    }

    if (write_password(password, options.length, options.trailing_newline) != WRITE_OK) {
        fprintf(stderr, "%s: failed to write password\n", program);
        secure_zero(password, options.length + 1U);
        free(password);
        return PASSMAKE_OUTPUT_FAILURE;
    }

    secure_zero(password, options.length + 1U);
    free(password);
    return PASSMAKE_OK;
}
