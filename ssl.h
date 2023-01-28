/*
 * MIT License
 *
 * Copyright (c) 2021 Jianhui Zhao <zhaojh329@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __SSL_H
#define __SSL_H

#include <stdbool.h>

enum {
    SSL_OK = 0,
    SSL_ERROR = -1,
    SSL_WANT_READ = -2,
    SSL_WANT_WRITE = -3
};

struct ssl {
    int err;
};

struct ssl_context;

const char *ssl_last_error_string(struct ssl *ssl, char *buf, int len);

struct ssl_context *ssl_context_new(bool server);
void ssl_context_free(struct ssl_context *ctx);

struct ssl *ssl_session_new(struct ssl_context *ctx, int sock);
void ssl_session_free(struct ssl *ssl);

int ssl_load_ca_cert_file(struct ssl_context *ctx, const char *file);
int ssl_load_cert_file(struct ssl_context *ctx, const char *file);
int ssl_load_key_file(struct ssl_context *ctx, const char *file);

int ssl_set_ciphers(struct ssl_context *ctx, const char *ciphers);

int ssl_set_require_validation(struct ssl_context *ctx, bool require);

void ssl_set_server_name(struct ssl *ssl, const char *name);

int ssl_read(struct ssl *ssl, void *buf, int len);
int ssl_write(struct ssl *ssl, const void *buf, int len);

int ssl_accept(struct ssl *ssl, void (*on_verify_error)(int error, const char *str, void *arg), void *arg);
int ssl_connect(struct ssl *ssl, void (*on_verify_error)(int error, const char *str, void *arg), void *arg);

#endif
