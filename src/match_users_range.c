/*
    MODULE -- Module to match an user based on static ip

    Copyright (C) Alberto Ornaghi

    $Id: match_users_ip.c 2661 2010-07-09 08:33:01Z alor $
*/

#include <main.h>
#include <hook.h>
#include <packet.h>

#include <match.h>
#include <match_users.h>

/* global vars */


/* proto */

void match_user_range_add(char *value, char *tag);

/*******************************************/

void match_user_range_add(char *value, char *tag)
{
   struct in_addr ip_start, ip_end;
   char *start, *end, *range = NULL; // avoid uninizialized warning

   SAFE_STRDUP(range, value);

   start = range;
   end = strchr(range, '-');
   if (end == NULL) {
      DEBUG_MSG(D_ERROR, "Invalid IP-RANGE %s in %s", value, GBL_CONF->redirected_users);
      goto cleanup;
   }
   start[end++ - start] = '\0';

   /* transform the target string into ip_addr struct */
   if (inet_pton(AF_INET, start, &ip_start) <= 0 || inet_pton(AF_INET, end, &ip_end) <= 0) {
      DEBUG_MSG(D_ERROR, "Invalid IP-RANGE %s in %s", value, GBL_CONF->redirected_users);
        goto cleanup;
   } else {
      struct ip_addr uip_start;
      struct ip_addr uip_end;
      struct timeval tv;

      if(ip_start.s_addr > ip_end.s_addr) {
         DEBUG_MSG(D_ERROR, "Invalid IP-RANGE %s in %s", value, GBL_CONF->redirected_users);
         goto cleanup;
      }

      /* fill the values */
      ip_addr_init(&uip_start, AF_INET, (u_char *)&ip_start);
      ip_addr_init(&uip_end, AF_INET, (u_char *)&ip_end);

      /* null end_time means there is no timeout */
      memset(&tv, 0, sizeof(struct timeval));

      /*
       * static-ip users are ALWAYS considered active.
       * that's all.
       * the hook to the IP level will trigger the tagging
       */
      active_user_add(&uip_start, &uip_end, NULL, tag, tv);
   }

   cleanup:
      SAFE_FREE(range);
}

/* EOF */

// vim:ts=3:expandtab

