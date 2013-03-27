/*
    MODULE -- decoder module

    Copyright (C) Alberto Ornaghi

    $Id: decode.c 2679 2010-07-14 15:46:43Z alor $
*/

#include <main.h>
#include <decode.h>
#include <threads.h>
#include <ui.h>
#include <packet.h>
#include <hook.h>
#include <capture.h>

#include <pcap/pcap.h>
#include <pthread.h>

/* globals */

struct decoder_entry {
   FUNC_DECODER_PTR(decoder);
};

static struct decoder_entry il_protocols_table[0xff];
static struct decoder_entry ll_protocols_table[0xffff];
static struct decoder_entry nl_protocols_table[0xff];

/* protos */

void __init data_init(void);
FUNC_DECODER(decode_data);

void decode_captured(u_char *param, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
void add_decoder(u_int8 level, u_int32 type, FUNC_DECODER_PTR(decoder));
void del_decoder(u_int8 level, u_int32 type);
void * get_decoder(u_int8 level, u_int32 type);

/*******************************************/

void decode_captured(u_char *param, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
   FUNC_DECODER_PTR(packet_decoder);
   struct packet_object *po;
   int len;
   u_char *data;
   size_t datalen;

   DEBUG_MSG(D_EXCESSIVE, "CAPTURED: 0x%04x bytes", pkthdr->caplen);

   /* save the timestamp of the last captured packet */
   GBL_STATS->rxtimestamp = pkthdr->ts.tv_sec;
   GBL_STATS->rx++;
   GBL_STATS->bytes += pkthdr->caplen;

   if (GBL_OPTIONS->read)
      /* update the offset pointer */
      GBL_PCAP->dump_off = ftell(pcap_file(GBL_PCAP_FIRST));

   /* bad packet */
   if (pkthdr->caplen > UINT16_MAX) {
      return;
   }

   /* bad packet */
   if (pkthdr->caplen > pkthdr->len) {
      return;
   }

   if (GBL_OPTIONS->analyze) {

      SAFE_CALLOC(data, pkthdr->caplen, sizeof(u_char));

      memcpy(data, pkt, pkthdr->caplen);

      datalen = pkthdr->caplen;

      /*
       * deal with truncated packets:
       * if someone has created a pcap file with the snaplen
       * too small we have to skip the packet (is not interesting for us)
       */
      if (GBL_PCAP->snaplen <= datalen) {
         //USER_MSG("Truncated packet detected, skipping...\n");
         return;
      }

      /* initialize the packet object structure to be passed through decoders */
      po = packet_create_object(data, datalen, &pkthdr->ts);
#if 0
      /* HOOK POINT: RECEIVED */
      hook_point(HOOK_RECEIVED, &po);
#endif

      /*
       * start the analysis through the decoders stack
       *
       * if the packet can be handled it will reach the top of the stack
       * where the decoder_data will dispatch it to the registered dissectors
       *
       * after this function the packet is completed (all flags set)
       */
      packet_decoder = get_decoder(LINK_LAYER, GBL_PCAP->dlt);
      BUG_IF(packet_decoder == NULL);
      packet_decoder(data, datalen, &len, po);

#if 0
      /* HOOK POINT: DECODED */
      hook_point(HOOK_DECODED, &po);
#endif

      SAFE_FREE(data);

      /* free the structure */
      packet_destroy_object(po);
   }

   /*
    * if it is the last packet of a pcap file
    * we have to exit the pcap loop
    */
   if (GBL_OPTIONS->read && GBL_PCAP->dump_size == GBL_PCAP->dump_off) {
      capture_stop();
   }

   return;
}


/*
 * add a decoder to the decoders table
 */
void add_decoder(u_int8 level, u_int32 type, FUNC_DECODER_PTR(decoder))
{
   /* use static arrays to speed up the access */
   switch(level) {
      case LINK_LAYER:
         il_protocols_table[type].decoder = decoder;
         break;
      case NET_LAYER:
         ll_protocols_table[type].decoder = decoder;
         break;
      case PROTO_LAYER:
         nl_protocols_table[type].decoder = decoder;
         break;
      default:
         printf("Unsupported decoder level.\n");
         exit(1);
         break;
   }

   return;
}

/*
 * get a decoder from the decoders table
 */

void * get_decoder(u_int8 level, u_int32 type)
{
   void *ret = NULL;

   /* with static array we have O(1) access instead of O(n) with lists */
   switch(level) {
      case LINK_LAYER:
         ret = (void *)il_protocols_table[type].decoder;
         break;
      case NET_LAYER:
         ret = (void *)ll_protocols_table[type].decoder;
         break;
      case PROTO_LAYER:
         ret = (void *)nl_protocols_table[type].decoder;
         break;
   }

   return ret;
}


/* EOF */

// vim:ts=3:expandtab

