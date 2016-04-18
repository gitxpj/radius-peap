#ifndef _RADIUS_PKG_H
#define _RADIUS_PKG_H

#include <stdlib.h>

typedef struct _radius_attribute {
    unsigned short type;
    unsigned char length;
    unsigned char *value;
} radius_attribute_t;

typedef struct _radius_package {
    unsigned char code;
    unsigned char identifier;
    unsigned short length;
    unsigned char authenticator[16];
    radius_attribute_t **attributes;
    int attr_len;
} radius_package_t;

radius_package_t *   radius_pkg_parse                 (char *buf, size_t buf_len);

unsigned char    *   radius_pkg_bytes                 (radius_package_t *package, int *outsize);

void                 radius_pkg_response_auth         (char *secret, radius_package_t *resp_pkg, char *out);

void                 radius_pkg_message_auth          (char *secret, radius_package_t *resp_pkg);

void                 radius_pkg_remove_attr           (int type, radius_package_t *resp_pkg);

void                 radius_pkg_add_attr              (radius_attribute_t *attr, radius_package_t *resp_pkg);

radius_attribute_t * radius_pkg_new_attr              (int type, unsigned char *value, unsigned char len);

int                  radius_pkg_size                  (radius_package_t *package);

void                 radius_pkg_free                  (radius_package_t *pkg);

void                 radius_pkg_new_request_auth      (unsigned char *md5);

void                 radius_pkg_fix_size              (radius_package_t *pkg);

void                 radius_pkg_fix_peap_key          (unsigned char *req_auth, unsigned char *client_auth, unsigned char *secret, int secret_len, unsigned char *p_secret, int p_secret_len, radius_package_t *pkg);

#endif