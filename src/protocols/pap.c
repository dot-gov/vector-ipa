/*
    MODULE -- PPP PAP decoder module

    Copyright (c) Alberto Ornaghi

    $Id: ppp_pap.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */

struct ppp_pap_header
{
   u_int8   version;
   u_int8   session;
   u_int16  id;
   u_int16  len;
   u_int16  proto;      /* this is actually part of the PPP header */
};

/* protos */

FUNC_DECODER(decode_ppp_pap);
void ppp_pap_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init ppp_pap_init(void)
{
   add_decoder(NET_LAYER, LL_TYPE_PAP, decode_ppp_pap);
}


FUNC_DECODER(decode_ppp_pap)
{
   FUNC_DECODER_PTR(next_decoder);
   struct ppp_pap_header *ppp_pap;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct ppp_pap_header);

   ppp_pap = (struct ppp_pap_header *)DECODE_DATA;

   /* HOOK POINT : HOOK_PACKET_PPP_PAP */
   hook_point(HOOK_PACKET_PPP_PAP, po);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

