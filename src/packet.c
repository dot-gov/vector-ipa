/*
    MODULE -- packet object handling

    Copyright (C) Alberto Ornaghi

    $Id: packet.c 790 2009-08-03 14:34:04Z alor $
*/

#include <main.h>
#include <packet.h>
#include <inet.h>
#include <ui.h>

/* protos... */

struct packet_object * packet_create_object(u_char * buf, size_t len, const struct timeval *ts);
inline int packet_destroy_object(struct packet_object *po);
struct packet_object * packet_dup(struct packet_object *po, u_char flag);

/* --------------------------- */

/*
 * associate the buffer to the packet object
 */

struct packet_object * packet_create_object(u_char *buf, size_t len, const struct timeval *ts)
{
   struct packet_object *po;

   SAFE_CALLOC(po, 1, sizeof(struct packet_object));

   /* set the buffer and the len of the received packet */
   SAFE_CALLOC(po->packet, len, sizeof(u_char));

   /* copy the buffer */
   memcpy(po->packet, buf, len);
   
   /* copy the buffer len */
   po->len = len;

   /* set the po timestamp */
   memcpy(&(po->ts), ts, sizeof(struct timeval));

   return (po);
}

/*
 * free the packet object memory
 */

inline int packet_destroy_object(struct packet_object *po)
{

   /*
    * the packet is a duplicate
    * we have to free even the packet buffer.
    */
   if (po->flags & PO_DUP) {

      SAFE_FREE(po->packet);
   } else {
      SAFE_FREE(po->packet);
      SAFE_FREE(po);
   }

   return 0;
}


/*
 * duplicate a po and return
 * the new allocated one
 */
struct packet_object * packet_dup(struct packet_object *po, u_char flag)
{
   struct packet_object *dup_po;

   SAFE_CALLOC(dup_po, 1, sizeof(struct packet_object));

   /*
    * copy the po over the dup_po
    * but this is not sufficient, we have to adjust all
    * the pointer to the po->packet.
    * so allocate a new packet, then recalculate the
    * pointers
    */
   memcpy(dup_po, po, sizeof(struct packet_object));

   /* copy only if the buffer exists */
   if ( (flag & PO_DUP_PACKET) && po->packet != NULL) {
      /* duplicate the po buffer */
      SAFE_CALLOC(dup_po->packet, po->len, sizeof(u_char));

      /* copy the buffer */
      memcpy(dup_po->packet, po->packet, po->len);
   } else {
      dup_po->len = 0;
      dup_po->packet = NULL;
   }

   /*
    * adjust all the pointers as the difference
    * between the old buffer and the pointer
    */
   dup_po->L2.header = dup_po->packet + (po->L2.header - po->packet);

   dup_po->L3.header = dup_po->packet + (po->L3.header - po->packet);
   dup_po->L3.options = dup_po->packet + (po->L3.options - po->packet);

   dup_po->L4.header = dup_po->packet + (po->L4.header - po->packet);
   dup_po->L4.options = dup_po->packet + (po->L4.options - po->packet);

   dup_po->DATA.data = dup_po->packet + (po->DATA.data - po->packet);

   /* this packet is a duplicate */
   dup_po->flags |= PO_DUP;

   return dup_po;
}


/* EOF */

// vim:ts=3:expandtab
