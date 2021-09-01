/*
 * netlink/list.h	Netlink List Utilities
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * LGPL 2.1 art. 5:
 * If such an object file uses only numerical parameters, data structure
 * layouts and accessors, and small macros and small inline functions (ten
 * lines or less in length), then the use of the object file is unrestricted,
 * regardless of whether it is legally a derivative work.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_LIST_H_
#define NETLINK_LIST_H_

#include <stddef.h>

struct nl_list_head
{
	struct nl_list_head *next;
	struct nl_list_head *prev;
};

#define NL_LIST_HEAD_INIT(name) \
  struct nl_list_head name = {&(name), &(name)}

static inline void NL_INIT_LIST_HEAD(struct nl_list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __nl_list_add(struct nl_list_head *obj,
		struct nl_list_head *prev,
		struct nl_list_head *next)
{
	obj->prev = prev;
	obj->next = next;
	prev->next = obj;
	next->prev = obj;
}

static inline void nl_list_add_tail(struct nl_list_head *obj,
		struct nl_list_head *head)
{
	__nl_list_add(obj, head->prev, head);
}

static inline void nl_list_add_head(struct nl_list_head *obj,
		struct nl_list_head *head)
{
	__nl_list_add(obj, head, head->next);
}

static inline void nl_list_del(struct nl_list_head *obj)
{
	obj->next->prev = obj->prev;
	obj->prev->next = obj->next;
}

static inline int nl_list_empty(struct nl_list_head *head)
{
	return head->next == head;
}

#define nl_offsetof(st, m) \
	((size_t)((char *)&((st *)0)->m - (char *)0))

#define nl_container_of(ptr, type, member) \
	((type *)((char *)(ptr) - nl_offsetof(type, member)))

#define nl_list_entry(ptr, type, member) \
	nl_container_of(ptr, type, member)

#define nl_list_at_tail(pos, head, member) \
	((pos)->member.next == (head))

#define nl_list_at_head(pos, head, member) \
	((pos)->member.prev == (head))

#define NL_LIST_HEAD(name) \
	struct nl_list_head name = { &(name), &(name) }

#define nl_list_first_entry(head, type, member)			\
	nl_list_entry((head)->next, type, member)

#define nl_list_for_each_entry(pos, head, member)				\
	for (pos = nl_list_entry((head)->next, typeof(*pos), member);	\
			&(pos)->member != (head); 	\
			(pos) = nl_list_entry((pos)->member.next, typeof(*(pos)), member))

#define nl_list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = nl_list_entry((head)->next, typeof(*pos), member),	\
			n = nl_list_entry(pos->member.next, typeof(*pos), member);	\
			&(pos)->member != (head); 					\
			pos = n, n = nl_list_entry(n->member.next, typeof(*n), member))

#define nl_init_list_head(head) \
	do { (head)->next = (head); (head)->prev = (head); } while (0)

#endif
