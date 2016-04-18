#ifndef _EAP_H
#define _EAP_H

#define MD5_MAC_LEN 16
typedef unsigned char u8;
typedef unsigned short u16;

#define WPA_PUT_BE16(a, val)            \
    do {                    \
        (a)[0] = ((u16) (val)) >> 8;    \
        (a)[1] = ((u16) (val)) & 0xff;  \
    } while (0)

void
encrypt_ms_key(const u8 *key, size_t key_len,
               u16 salt,
               const u8 *req_authenticator,
               const u8 *secret, size_t secret_len,
               u8 *ebuf, size_t *elen);

u8 *
decrypt_ms_key(const u8 *key, size_t len,
               const u8 *req_authenticator,
               const u8 *secret, size_t secret_len, size_t *reslen);

#endif