/*
    MODULE -- MPLS decoder module

    Copyright (c) Alberto Ornaghi

    $Id: mpls.c 2657 2010-07-07 07:18:33Z alor $
*/

#include <main.h>
#include <decode.h>
#include <capture.h>

/* globals */

struct mpls_header
{
   u_int32  shim;
   /*
    * 20 bit for the label
    * 3 bit for priority
    * 1 bit for stack bit (1 is the end of the stack, 0 is in the stack: other mpls headers)
    * 8 bit for time to live
    */
};

/* protos */

FUNC_DECODER(decode_mpls);
void mpls_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init mpls_init(void)
{
   add_decoder(NET_LAYER, LL_TYPE_MPLS, decode_mpls);
}


FUNC_DECODER(decode_mpls)
{
   FUNC_DECODER_PTR(next_decoder);
   struct mpls_header *mpls;

   DEBUG_MSG(D_EXCESSIVE, "%s", __FUNCTION__);

   DECODED_LEN = sizeof(struct mpls_header);

   mpls = (struct mpls_header *)DECODE_DATA;

   /* HOOK POINT : HOOK_PACKET_mpls */
   hook_point(HOOK_PACKET_MPLS, po);

   /* check the stack bit (9th bit) */
   if (mpls->shim & 0x00000100) {
      /* leave the control to the IP decoder */
      next_decoder = get_decoder(NET_LAYER, LL_TYPE_IP);
   } else {
      /* leave the control to the another MPLS header */
      next_decoder = get_decoder(NET_LAYER, LL_TYPE_MPLS);
   }

   EXECUTE_DECODER(next_decoder);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

