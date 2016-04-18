#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>

#include "eap.h"

static int
openssl_digest_vector(const EVP_MD *type, int non_fips,
                 size_t num_elem, const u8 *addr[],
                 const size_t *len, u8 *mac)
{
    EVP_MD_CTX ctx;
    size_t i;
    unsigned int mac_len;

    EVP_MD_CTX_init(&ctx);
#ifdef CONFIG_FIPS
#ifdef OPENSSL_FIPS
    if (non_fips)
        EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif /* OPENSSL_FIPS */
#endif /* CONFIG_FIPS */
    if (!EVP_DigestInit_ex(&ctx, type, NULL)) {
        return -1;
    }
    for (i = 0; i < num_elem; i++) {
        if (!EVP_DigestUpdate(&ctx, addr[i], len[i])) {
            return -1;
        }
    }
    if (!EVP_DigestFinal(&ctx, mac, &mac_len)) {
        return -1;
    }

    return 0;
}

void
encrypt_ms_key(
               const u8 *key,
               size_t key_len,
               u16 salt,
               const u8 *req_authenticator,
               const u8 *secret, size_t secret_len,
               u8 *ebuf, size_t *elen)
{
    int i, len, first = 1;
    u8 hash[MD5_MAC_LEN], saltbuf[2], *pos;
    const u8 *addr[3];
    size_t _len[3];

    WPA_PUT_BE16(saltbuf, salt);

    len = 1 + key_len;
    if (len & 0x0f) {
        len = (len & 0xf0) + 16;
    }
    memset(ebuf, 0, len);
    ebuf[0] = key_len;
    memcpy(ebuf + 1, key, key_len);

    *elen = len;

    pos = ebuf;
    while (len > 0) {
        /* b(1) = MD5(Secret + Request-Authenticator + Salt)
         * b(i) = MD5(Secret + c(i - 1)) for i > 1 */
        addr[0] = secret;
        _len[0] = secret_len;
        if (first) {
            addr[1] = req_authenticator;
            _len[1] = MD5_MAC_LEN;
            addr[2] = saltbuf;
            _len[2] = sizeof(saltbuf);
        } else {
            addr[1] = pos - MD5_MAC_LEN;
            _len[1] = MD5_MAC_LEN;
        }
        openssl_digest_vector(EVP_md5(), 0, first ? 3 : 2, addr, _len, hash);
        first = 0;

        for (i = 0; i < MD5_MAC_LEN; i++)
            *pos++ ^= hash[i];

        len -= MD5_MAC_LEN;
    }
}

u8 *
decrypt_ms_key(const u8 *key, size_t len,
               const u8 *req_authenticator,
               const u8 *secret, size_t secret_len, size_t *reslen)
{
    u8 *plain, *ppos, *res;
    const u8 *pos;
    size_t left, plen;
    u8 hash[MD5_MAC_LEN];
    int i, first = 1;
    const u8 *addr[3];
    size_t elen[3];

    /* key: 16-bit salt followed by encrypted key info */

    if (len < 2 + 16)
        return NULL;

    pos = key + 2;
    left = len - 2;
    if (left % 16) {
        printf("Invalid ms key len %lu\n", (unsigned long) left);
        return NULL;
    }

    plen = left;
    ppos = plain = malloc(plen);
    if (plain == NULL)
        return NULL;
    plain[0] = 0;

    while (left > 0) {
        /* b(1) = MD5(Secret + Request-Authenticator + Salt)
         * b(i) = MD5(Secret + c(i - 1)) for i > 1 */

        addr[0] = secret;
        elen[0] = secret_len;
        if (first) {
            addr[1] = req_authenticator;
            elen[1] = MD5_MAC_LEN;
            addr[2] = key;
            elen[2] = 2; /* Salt */
        } else {
            addr[1] = pos - MD5_MAC_LEN;
            elen[1] = MD5_MAC_LEN;
        }

        openssl_digest_vector(EVP_md5(), 0, first ? 3 : 2, addr, elen, hash);

        first = 0;

        for (i = 0; i < MD5_MAC_LEN; i++)
            *ppos++ = *pos++ ^ hash[i];
        left -= MD5_MAC_LEN;
    }

    if (plain[0] == 0 || plain[0] > plen - 1) {
        printf("Failed to decrypt MPPE key\n");
        free(plain);
        return NULL;
    }

    res = malloc(plain[0]);
    if (res == NULL) {
        free(plain);
        return NULL;
    }
    memcpy(res, plain + 1, plain[0]);
    if (reslen)
        *reslen = plain[0];
    free(plain);
    return res;
}

void
hex2bytes(const char* source, unsigned char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte  = toupper(source[i + 1]);

        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;

        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return ;
}
