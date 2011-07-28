/*
    MODULE -- hook points handling

    Copyright (C) Alberto Ornaghi

    $Id: hook.c 790 2009-08-03 14:34:04Z alor $
*/

#include <main.h>
#include <hook.h>
#include <packet.h>

#include <pthread.h>

struct hook_list {
   void (*func)(struct packet_object *po);
   LIST_ENTRY (hook_list) next;
};

/* global data */

/* the list for the HOOK_* */
static LIST_HEAD(, hook_list) hook_list_head[HOOK_PACKET_MAX];

/* protos... */

void hook_point(int point, struct packet_object *po);
void hook_add(int point, void (*func)(struct packet_object *po) );
int hook_del(int point, void (*func)(struct packet_object *po) );

/*******************************************/

/* execute the functions registered in that hook point */

void hook_point(int point, struct packet_object *po)
{
   struct hook_list *current;

   LIST_FOREACH(current, &hook_list_head[point], next)
      current->func(po);

   return;
}


/* add a function to an hook point */

void hook_add(int point, void (*func)(struct packet_object *po) )
{
   struct hook_list *newelem;

   SAFE_CALLOC(newelem, 1, sizeof(struct hook_list));

   newelem->func = func;

   LIST_INSERT_HEAD(&hook_list_head[point], newelem, next);
}

/* remove a function from an hook point */

int hook_del(int point, void (*func)(struct packet_object *po) )
{
   struct hook_list *current;

   LIST_FOREACH(current, &hook_list_head[point], next) {
      if (current->func == func) {
         LIST_REMOVE(current, next);
         SAFE_FREE(current);
         DEBUG_MSG(D_DEBUG, "hook_del -- %d [%p]", point, func);
         return ESUCCESS;
      }
   }

   return -ENOTFOUND;
}


/* EOF */

// vim:ts=3:expandtab

