#include <stdint.h>
#include <stddef.h>

// Function prototype
int randombytes(uint8_t *out, size_t outlen);

#if defined(__APPLE__)
#include <Security/SecRandom.h>
int randombytes(uint8_t *out, size_t outlen) {
    return SecRandomCopyBytes(kSecRandomDefault, outlen, out);
}

#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
int randombytes(uint8_t *out, size_t outlen) {
    return BCryptGenRandom(NULL, out, (ULONG)outlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

#elif defined(__linux__) || defined(__ANDROID__)
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
int randombytes(uint8_t *out, size_t outlen) {
    size_t done = 0;
    int fd;
    do {
        fd = open("/dev/urandom", O_RDONLY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return -1;
    while (done < outlen) {
        ssize_t ret = read(fd, out + done, outlen - done);
        if (ret < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (ret == 0) {
            /* Unexpected end of file: the buffer was not filled. */
            close(fd);
            return -1;
        }
        done += (size_t)ret;
    }
    close(fd);
    return 0;
}

#else
#error "Unsupported platform — you must implement randombytes()"
#endif
