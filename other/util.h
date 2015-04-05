#include <sys/types.h>
#include <inttypes.h>

#ifdef NEED_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

int bcrypt_pbkdf(const char *pass, size_t pass_len, const uint8_t *salt,
         size_t salt_len, uint8_t *key, size_t key_len, unsigned int rounds);

