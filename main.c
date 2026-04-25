#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

enum {
    MIN_PASSWORD_LENGTH = 3,
    MAX_PASSWORD_LENGTH = 4096,
    RANDOM_POOL_SIZE = 4096
};

static const char ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789";

static const size_t ALPHABET_LENGTH = sizeof(ALPHABET) - 1U;

typedef struct {
    size_t length;
    bool length_set;
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
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len > 0U) {
        *p = 0U;
        ++p;
        --len;
    }
}

static void print_help(const char *program)
{
    printf("Usage:\n");
    printf("  %s COUNT [--no-newline]\n", program);
    printf("  %s [--length COUNT | --count COUNT] [--no-newline]\n", program);
    printf("\n");
    printf("Generate a cryptographically secure password using only A-Z, a-z, and 0-9.\n");
    printf("Generated passwords always contain at least one uppercase letter, one lowercase\n");
    printf("letter, and one digit.\n");
    printf("\n");
    printf("Options:\n");
    printf("  --length COUNT       Optional alias for positional COUNT (%d-%d characters).\n",
           MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
    printf("  --length=COUNT      Same as --length COUNT.\n");
    printf("  --count COUNT        Optional alias for positional COUNT.\n");
    printf("  --count=COUNT       Same as --count COUNT.\n");
    printf("  --no-newline         Do not append a trailing newline.\n");
    printf("  --security           Explain the program's cryptographic security design.\n");
    printf("  --help               Show this help text and exit.\n");
}

static void print_security(void)
{
    printf("Cryptographic security design:\n");
    printf("\n");
    printf("- Randomness comes from the Linux kernel CSPRNG through getrandom(2).\n");
    printf("- If getrandom(2) is unavailable, /dev/urandom is used as a compatibility\n");
    printf("  fallback.\n");
    printf("- Password characters are chosen from 62 symbols: A-Z, a-z, and 0-9.\n");
    printf("- Rejection sampling is used when mapping random bytes to characters, so\n");
    printf("  character selection does not suffer from modulo bias.\n");
    printf("- The whole password is regenerated until it contains at least one uppercase\n");
    printf("  letter, one lowercase letter, and one digit. This keeps accepted passwords\n");
    printf("  uniformly distributed across the allowed set instead of forcing fixed\n");
    printf("  positions for required character classes.\n");
    printf("- Random-byte buffers and the generated password buffer are cleared before\n");
    printf("  exit to reduce leftover sensitive data in process memory.\n");
    printf("\n");
    printf("Security still depends on choosing a long enough password, keeping the output\n");
    printf("private, and using it with systems that store and handle passwords safely.\n");
}

static bool parse_length(const char *text, size_t *length, char *message, size_t message_size)
{
    unsigned long parsed = 0UL;
    const unsigned char *cursor = (const unsigned char *)text;

    if (text == NULL || text[0] == '\0') {
        (void)snprintf(message, message_size, "length must be a decimal integer");
        return false;
    }

    while (*cursor != '\0') {
        if (*cursor < (unsigned char)'0' || *cursor > (unsigned char)'9') {
            (void)snprintf(message, message_size, "length must be a decimal integer");
            return false;
        }
        ++cursor;
    }

    errno = 0;
    parsed = strtoul(text, NULL, 10);
    if (errno == ERANGE) {
        (void)snprintf(message, message_size, "length is too large");
        return false;
    }

    if (parsed < (unsigned long)MIN_PASSWORD_LENGTH) {
        (void)snprintf(message, message_size,
                       "length must be at least %d to include all required character types",
                       MIN_PASSWORD_LENGTH);
        return false;
    }

    if (parsed > (unsigned long)MAX_PASSWORD_LENGTH) {
        (void)snprintf(message, message_size, "length must be no more than %d",
                       MAX_PASSWORD_LENGTH);
        return false;
    }

    *length = (size_t)parsed;
    return true;
}

static bool set_length_once(Options *options, const char *value, char *message, size_t message_size)
{
    size_t parsed = 0U;

    if (options->length_set) {
        (void)snprintf(message, message_size, "length was provided more than once");
        return false;
    }

    if (!parse_length(value, &parsed, message, message_size)) {
        return false;
    }

    options->length = parsed;
    options->length_set = true;
    return true;
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

static bool parse_args(int argc, char **argv, Options *options, bool *help_requested,
                       bool *security_requested, char *message, size_t message_size)
{
    bool parse_options = true;

    options->length = 0U;
    options->length_set = false;
    options->trailing_newline = true;
    *help_requested = false;
    *security_requested = false;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        const char *value = NULL;

        if (parse_options && strcmp(arg, "--help") == 0) {
            *help_requested = true;
            return true;
        }

        if (parse_options && strcmp(arg, "--security") == 0) {
            *security_requested = true;
            return true;
        }

        if (parse_options && strcmp(arg, "--") == 0) {
            parse_options = false;
            continue;
        }

        if (parse_options && strcmp(arg, "--no-newline") == 0) {
            options->trailing_newline = false;
            continue;
        }

        if (parse_options && (strcmp(arg, "--length") == 0 || strcmp(arg, "--count") == 0)) {
            if (i + 1 >= argc) {
                (void)snprintf(message, message_size, "%s requires a value", arg);
                return false;
            }

            ++i;
            if (!set_length_once(options, argv[i], message, message_size)) {
                return false;
            }
            continue;
        }

        if (parse_options && (option_value(arg, "--length", &value)
                              || option_value(arg, "--count", &value))) {
            if (!set_length_once(options, value, message, message_size)) {
                return false;
            }
            continue;
        }

        if (parse_options && strncmp(arg, "--", 2U) == 0) {
            (void)snprintf(message, message_size, "unknown option: %s", arg);
            return false;
        }

        if (!set_length_once(options, arg, message, message_size)) {
            return false;
        }
    }

    if (!options->length_set) {
        (void)snprintf(message, message_size, "missing length");
        return false;
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

static int random_alphabet_index(RandomPool *pool, size_t *index)
{
    const unsigned int bucket_size = 256U;
    const unsigned int limit = bucket_size - (bucket_size % (unsigned int)ALPHABET_LENGTH);

    for (;;) {
        unsigned char byte = 0U;

        if (random_pool_byte(pool, &byte) != 0) {
            return -1;
        }

        if ((unsigned int)byte < limit) {
            *index = (size_t)((unsigned int)byte % (unsigned int)ALPHABET_LENGTH);
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

static int generate_password(char *password, size_t length)
{
    RandomPool pool;

    random_pool_init(&pool);

    for (;;) {
        bool has_upper = false;
        bool has_lower = false;
        bool has_digit = false;

        for (size_t i = 0U; i < length; ++i) {
            size_t index = 0U;

            if (random_alphabet_index(&pool, &index) != 0) {
                secure_zero(&pool, sizeof(pool));
                return -1;
            }

            password[i] = ALPHABET[index];
            classify_char(password[i], &has_upper, &has_lower, &has_digit);
        }

        if (has_upper && has_lower && has_digit) {
            password[length] = '\0';
            secure_zero(&pool, sizeof(pool));
            return 0;
        }
    }
}

static int write_password(const char *password, size_t length, bool trailing_newline)
{
    if (fwrite(password, 1U, length, stdout) != length) {
        return -1;
    }

    if (trailing_newline && fputc('\n', stdout) == EOF) {
        return -1;
    }

    if (fflush(stdout) == EOF) {
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    Options options;
    bool help_requested = false;
    bool security_requested = false;
    char message[128];
    char *password = NULL;
    const char *program = (argc > 0 && argv[0] != NULL) ? base_name(argv[0]) : "passmake";

    message[0] = '\0';

    if (!parse_args(argc, argv, &options, &help_requested, &security_requested, message,
                    sizeof(message))) {
        fprintf(stderr, "%s: %s\n", program, message);
        fprintf(stderr, "Try '%s --help' for usage.\n", program);
        return EXIT_FAILURE;
    }

    if (help_requested) {
        print_help(program);
        return EXIT_SUCCESS;
    }

    if (security_requested) {
        print_security();
        return EXIT_SUCCESS;
    }

    password = malloc(options.length + 1U);
    if (password == NULL) {
        fprintf(stderr, "%s: memory allocation failed\n", program);
        return EXIT_FAILURE;
    }

    if (generate_password(password, options.length) != 0) {
        fprintf(stderr, "%s: failed to read secure random bytes\n", program);
        secure_zero(password, options.length + 1U);
        free(password);
        return EXIT_FAILURE;
    }

    if (write_password(password, options.length, options.trailing_newline) != 0) {
        fprintf(stderr, "%s: failed to write password\n", program);
        secure_zero(password, options.length + 1U);
        free(password);
        return EXIT_FAILURE;
    }

    secure_zero(password, options.length + 1U);
    free(password);
    return EXIT_SUCCESS;
}
