#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

#include "radiuspkg.h"

#include "eap.h"

#define ATRRIBUTE_BUF_SIZE 50

void
debug_hex(char *prefix, char *buf, int buf_len) {
    printf("%s_HEX_DEBUG:\n", prefix);
    for (int i = 0; i < buf_len; ++i)
    {
        printf("%.2x", (unsigned char)buf[i]);
    }
    printf("\n");
}

radius_package_t *
radius_pkg_parse(char *buf, size_t buf_len) {
    if (buf_len > 20) {
        radius_package_t *pkg = malloc(sizeof(radius_package_t));
        pkg->code = buf[0];
        pkg->identifier = buf[1];
        pkg->attr_len = 0;

        unsigned short *ptr = &pkg->length;
        *((char *)ptr + 1) = *(buf + 2);
        *((char *)ptr) = *(buf + 3);

        memcpy(pkg->authenticator, buf + 4, 16);

        // parse attributes
        int offset = 20;

        pkg->attributes = malloc(sizeof(radius_attribute_t*) * ATRRIBUTE_BUF_SIZE);

        while (offset < buf_len) {

            pkg->attributes[pkg->attr_len] = malloc(sizeof(radius_attribute_t));
            radius_attribute_t *a = pkg->attributes[pkg->attr_len];

            a->length = *(buf + offset + 1);

            a->type = (unsigned short)buf[offset];
            a->value = malloc(a->length - 2);
            memcpy(a->value, buf + offset + 2, a->length - 2);

            pkg->attr_len++;
            offset += a->length;
        }

        pkg->attributes = realloc(pkg->attributes, sizeof(radius_attribute_t*) * pkg->attr_len);


        return pkg;
    } else {
        return NULL;
    }
}

unsigned char *
radius_pkg_bytes(radius_package_t *package, int *outsize) {
    int pkg_len = radius_pkg_size(package);

    unsigned char *buf = malloc(pkg_len);

    buf[0] = package->code;
    buf[1] = package->identifier;

    memcpy(buf + 4, package->authenticator, 16);

    unsigned short offset = 20;

    for (int i = 0; i < package->attr_len; ++i)
    {
        radius_attribute_t *attr = package->attributes[i];
        buf[offset] = attr->type;
        buf[offset + 1] = attr->length;
        memcpy(buf + offset + 2, attr->value, attr->length - 2);
        offset += attr->length;
    }

    unsigned short *ptr = &offset;
    buf[2] = *((char *)ptr + 1);
    buf[3] = *((char *)ptr);

    if (outsize) {
        *outsize = offset;
    }

    return buf;
}

int
radius_pkg_size(radius_package_t *package) {
    int count = 20;
    for (int i = 0; i < package->attr_len; ++i)
    {
        count += package->attributes[i]->length;
    }
    return count;
}

void
radius_pkg_free(radius_package_t *pkg) {
    for (int i = 0; i < pkg->attr_len; ++i)
    {
        free(pkg->attributes[i]->value);
        free(pkg->attributes[i]);
    }
    free(pkg->attributes);
    free(pkg);
}

void
radius_pkg_response_auth(char *secret, radius_package_t *resp_pkg, char *out) {
    int buf_len = 0;
    unsigned char *buf = radius_pkg_bytes(resp_pkg, &buf_len);
    int secret_len = strlen(secret);

    buf = realloc(buf, buf_len + secret_len);

    memcpy(buf + buf_len, secret, secret_len);

    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, buf, buf_len + secret_len);
    MD5_Final((unsigned char *)out, &c);

    // debug_hex("RESPONSE", buf, buf_len + secret_len);

    free(buf);
}

void
radius_pkg_message_auth(char *secret, radius_package_t *resp_pkg) {
    for (int i = 0; i < resp_pkg->attr_len; ++i)
    {
        radius_attribute_t *attr = resp_pkg->attributes[i];

        // Message-Authenticator
        if (attr->type == 80) {
            memset(attr->value, 0, 16);

            int recalc_len = 0;
            unsigned char *recalc = (unsigned char *)radius_pkg_bytes(resp_pkg, &recalc_len);

            HMAC(EVP_md5(), secret, strlen(secret), recalc, recalc_len, attr->value, NULL);

            // debug_hex("REQUEST_MSG_AUTH", recalc, recalc_len);

            free(recalc);
        }
    }
}

void
radius_pkg_remove_attr(int type, radius_package_t *resp_pkg) {
    radius_attribute_t **pkgs = malloc(sizeof(radius_attribute_t*) * ATRRIBUTE_BUF_SIZE);

    int j = 0;

    for (int i = 0; i < resp_pkg->attr_len; ++i)
    {
        radius_attribute_t *attr = resp_pkg->attributes[i];
        if (attr->type == type) {
            free(attr->value);
            free(attr);
        } else {
            pkgs[j] = attr;
            j++;
        }
    }

    pkgs = realloc(pkgs, sizeof(radius_attribute_t*) * j);

    resp_pkg->attributes = pkgs;
    resp_pkg->attr_len = j;
    radius_pkg_fix_size(resp_pkg);
}

void
radius_pkg_add_attr(radius_attribute_t *attr, radius_package_t *resp_pkg) {
    resp_pkg->attr_len++;
    resp_pkg->attributes = realloc(resp_pkg->attributes, sizeof(radius_attribute_t*) * resp_pkg->attr_len);
    resp_pkg->attributes[(resp_pkg->attr_len - 1)] = attr;
    radius_pkg_fix_size(resp_pkg);
}

radius_attribute_t *
radius_pkg_new_attr(int type, unsigned char *value, unsigned char len) {
    radius_attribute_t *attr = malloc(sizeof(radius_attribute_t));
    attr->type = type;
    attr->length = len + 2;
    attr->value = value;
    return attr;
}

void
radius_pkg_new_request_auth(unsigned char *md5) {
    time_t t = time(0);
    srand(t);
    char temp[50];
    memset(&temp, 0, 50);
    sprintf(temp, "A%ld%dZ", t, rand());

    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, temp, 50);
    MD5_Final(md5, &c);
}

void
radius_pkg_fix_size(radius_package_t *pkg) {
    pkg->length = radius_pkg_size(pkg);
}

void
radius_pkg_fix_peap_key(unsigned char *req_auth,
    unsigned char *client_auth,
    unsigned char *secret, int secret_len,
    unsigned char *p_secret, int p_secret_len,
    radius_package_t *pkg) {

    for (int i = 0; i < pkg->attr_len; ++i)
    {
        radius_attribute_t *attr = pkg->attributes[i];
        //Vendor-Specific
        if (attr->type == 26) {
            // MS-MPPE-Send-Key & MS-MPPE-Receive-Key
            if (attr->value[4] == 16 || attr->value[4] == 17) {
                unsigned char *value = attr->value + 6;
                int value_len = attr->length - 8;
                size_t reslen = 0;
                unsigned char *raw_key = decrypt_ms_key(value, value_len, req_auth, p_secret, p_secret_len, &reslen);
                unsigned short salt = rand() | 0x8000;

                WPA_PUT_BE16(value, salt);

                size_t len = 0;
                encrypt_ms_key(raw_key, reslen, salt, client_auth, secret, secret_len, value + 2, &len);

                printf("fix package success!\n");
                free(raw_key);
            }
        }
    }
}
