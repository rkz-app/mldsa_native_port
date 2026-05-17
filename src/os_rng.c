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
int randombytes(uint8_t *out, size_t outlen) {
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) return -1;
    read(fd, out, outlen);
    close(fd);
    return 0;
}

#else
#error "Unsupported platform — you must implement randombytes()"
#endif
