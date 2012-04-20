/*
 * slab.c - Slab Memory alloctor
 *
 * Copywrite (c) 2011 -2012 wzt
 *
 * 
 *  -------     ------     ------    ------
 *  |cache|-->  |slab| --> |slab| -->|slab|
 *  -------     ------     ------    ------
 *  |cache|
 *  -----
 *  |cache| ... 
 *  -----      ------     ------    ------
 *  |cache|--> |slab| --> |slab| -->|slab|
 *  -----      ------     -----     ------
 *  |cache| ...
 *  -------    
 *  |cache|
 *  ------- 
 *  |cache|-->|slab|-->|slab| -->|slab|
 *  -------   ------   ------    ------
 *
 *
 * current support:
 *
 * - basic implement for slab alloctor.
 * - hardware cache support.
 * - slab expand support.
 * - genernal slab and slab cache support.
 *
 * todo:
 *
 * - slab obj cache support.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <pthread.h>

#include "list.h"
#include "slab.h"

static int slab_size[SLAB_SIZE_NUM] = {8, 16, 32, 64, 128, 256, 512, 1024, 2048};

void __init_slab(struct slab_cache *slab_cache, void *addr, int size);

void __show_slab_list(struct list_head *list_head)
{
	struct slab *slab;
	struct list_head *p;

	if (list_empty(list_head))
		return ;

	list_for_each(p, list_head) {
		slab = list_entry(p, struct slab, list);
		if (slab) {
			printf("obj num: %d\tfree_num: %d\tbase: 0x%x\n",
				slab->obj_num, slab->free_num, slab->base);
		}
	}
}

void show_slab_list(struct thread_mem *thread_mem)
{
	int idx;

	for (idx = 0; idx < thread_mem->slab_cache_array_size; idx++) {
		printf("slab size: %d slab num: %d free num: %d color num: %d\n",
			thread_mem->slab_cache_array[idx].slab_size, 
			thread_mem->slab_cache_array[idx].slab_num,
			thread_mem->slab_cache_array[idx].free_num,
			thread_mem->slab_cache_array[idx].color_num);
		__show_slab_list(&(thread_mem->slab_cache_array[idx].list));
	}
}

/* bufctl just behind the slab struct. */
unsigned int *slab_bufctl(struct slab *slab)
{
	return (unsigned int *)(slab + 1);
}

/* get an obj from a slab. */
void *get_slab_obj(struct slab *slab, struct slab_cache *slab_cache)
{
	void *obj;

	obj = slab->base + slab_cache->slab_size * slab->free_idx;

	slab->free_idx = slab_bufctl(slab)[slab->free_idx];

	slab->free_num--;
	slab_cache->free_num--;

	return obj;
}

void *get_obj_from_cache(struct slab_obj_cache *obj_cache)
{
	--obj_cache->curr_obj;

	return (void *)((unsigned int *)(obj_cache->entry) + obj_cache->curr_obj);
}

void set_slab_obj_cache(struct slab *slab, struct slab_cache *slab_cache)
{
	void *obj;
	int idx;

	//assert(slab_cache != NULL && slab_cache->obj_cache != NULL);

	slab_cache->obj_cache->entry = (void *)malloc(sizeof(int) * slab_cache->slab_num);
	if (!slab_cache->obj_cache->entry) {
		fprintf(stderr, "malloc failed %d.\n", __LINE__);
		exit(-1);
	}

	/* allocte obj from end to head. */
	slab_cache->obj_cache->curr_obj = slab->obj_num;
	slab_cache->obj_cache->limit = slab->obj_num;

	for (idx = 0; idx < slab->obj_num - 1; idx++) {
		*(((unsigned int *)slab_cache->obj_cache->entry + idx)) = 
			get_slab_obj(slab, slab_cache);
	}
	slab_cache->obj_cache->curr_obj = 0;
}

int check_slab_size(int size)
{
        int i;

        for (i = 0; i < SLAB_SIZE_NUM; i++) {
                if (size <= slab_size[i])
                        return i;
        }

        return -1;
}

/* 
 * expand a new slab with PAGE_SIZE. 
 */
void *expand_slab(struct slab_cache *slab_cache)
{
	void *new_slab = NULL;

	new_slab = get_new_page(PAGE_ORDER_ZERO, MEM_ALLOC_GLIBC);
	if (!new_slab) {
		fprintf(stderr, "alloc_page failed.\n");
		return NULL;
	}
	
	__init_slab(slab_cache, new_slab, slab_cache->slab_size);
	
	slab_cache->slab_num++;

	return new_slab;
}

void *slab_alloc(struct thread_mem *thread_mem, int size)
{
	struct slab *s = NULL;
	struct list_head *p = NULL;
	void *obj;
	int idx;

	assert(thread_mem != NULL && size >= 0);

	if (size < 8 || size > 2048)
		return malloc(size);

	idx = check_slab_size(size);
	if (idx == -1)
		return malloc(size);

	if (thread_mem->slab_cache_array[idx].obj_cache->curr_obj != 0) {
		obj = get_obj_from_cache(thread_mem->slab_cache_array[idx].obj_cache);

		return obj;
	}

	if (!(thread_mem->slab_cache_array[idx].free_num)) {
		fprintf(stdout, "expand slab obj in %d.\n", idx);
		if (!(s = expand_slab(&(thread_mem->slab_cache_array[idx])))) {
			fprintf(stderr, "expand slab failed.\n");
			return NULL;
		}
		obj = get_slab_obj(s, &(thread_mem->slab_cache_array[idx]));
		return obj;
	}

	list_for_each(p, (&(thread_mem->slab_cache_array[idx].list))) {
		s = list_entry(p, struct slab, list);
		if (s && s->free_num) {
			obj = get_slab_obj(s, &((thread_mem->slab_cache_array[idx])));
			return obj;
		}
	}

	return NULL;
}

/*
 * support for slab_free & kmem_cache_free.
 */
struct slab *search_slab(void *addr, struct list_head *list_head)
{
	struct slab *slab;
	struct list_head *p;

	assert(list_head != NULL);

	list_for_each(p, list_head) {
		slab = list_entry(p, struct slab, list);
		if (slab) { 
			if (slab->base <= addr && addr <= ((void *)slab + PAGE_SIZE))
				return slab;
		}
	}

	return NULL;
}

void *put_slab_obj(struct slab *slab, void *obj, struct slab_cache *slab_cache)
{
	int obj_idx;

	assert(slab != NULL && slab_cache != NULL);

/*
	printf("obj: %x, slab->base: %x slab size: %d\n", 
		obj, slab->base, slab_cache->slab_size);
*/

	obj_idx = (obj - slab->base) / slab_cache->slab_size;
	//printf("obj_idx: %d\n", obj_idx);
	
	slab_bufctl(slab)[obj_idx] = slab->free_idx;
	slab->free_idx = obj_idx;

	slab->free_num++;
	slab_cache->free_num++;
}

void slab_free(struct thread_mem *thread_mem, void *addr, int size)
{
	struct slab *slab;
	int cache_idx;

	assert(thread_mem != NULL);

	if (!addr)
		return ;

	cache_idx = check_slab_size(size);
	if (cache_idx < 0 || cache_idx >= SLAB_SIZE_NUM)
		return ;

	slab = search_slab(addr, &(thread_mem->slab_cache_array[cache_idx].list));
	if (!slab) {
		fprintf(stderr, "search slab failed with addr: %p\n", addr);
		return ;
	}

	put_slab_obj(slab, addr, &(thread_mem->slab_cache_array[cache_idx]));
}

int compute_slab_obj_num(int obj_size, int slab_size)
{
	return (slab_size - sizeof(struct slab)) / (obj_size + sizeof(int));
}

/*
 * compute slab color num for hardware cache.
 */
int compute_slab_color_num(int obj_size, int slab_size)
{
	return (slab_size - sizeof(struct slab)) % (obj_size + sizeof(int));
}

int get_slab_color(struct slab_cache *slab_cache)
{
	if (slab_cache->color_next >= slab_cache->color_num) {
		slab_cache->color_next = 0;
		return 0;
	}
	else {
		return ++slab_cache->color_next;
	}
}

void *set_slab_base_addr(void *addr, struct slab *new_slab)
{
/*
	return (void *)(ALIGN((unsigned int)(addr + sizeof(struct slab) +
                (new_slab->obj_num * sizeof(int))), DEFAULT_ALIGN));
*/
	return (void *)(addr + sizeof(struct slab) + new_slab->obj_num * sizeof(int));
}

/* 
 * support for CPU hardware cache.
 */
void *fix_slab_base_addr(void *addr, int color)
{
	return (void *)(addr + color);
}

/* 
 * all the slab managment builtin the front of the slab, next is bufctl
 * array which is a sample link list of obj. the end of the slab maybe
 * not used, it can be used for slab color for hardware cache.
 *
 * the slab struct like this:
 *
 * +-----------------------------------------------+
 * | struct slab | bufctl | obj | obj | ...| color |
 * +-----------------------------------------------+
 * 
 */
void __init_slab(struct slab_cache *slab_cache, void *addr, int size)
{
	struct slab *new_slab = (struct slab *)addr;
	void *base;
	int idx;

	new_slab->obj_num = compute_slab_obj_num(size, PAGE_SIZE);
	new_slab->free_num = new_slab->obj_num;

	for (idx = 0; idx < new_slab->obj_num - 1; idx++)
		slab_bufctl(new_slab)[idx] = idx + 1;
	slab_bufctl(new_slab)[idx] = -1;

        if (slab_cache->ctor)
                slab_cache->ctor();

        slab_cache->free_num += new_slab->free_num;
        slab_cache->color_next = get_slab_color(slab_cache);
	//printf("!%d\n", slab_cache->color_next);
	
	//assert(slab_cache->obj_cache);
	//set_slab_obj_cache(new_slab, slab_cache);

	new_slab->free_idx = 0;
	list_add_tail(&(new_slab->list), &(slab_cache->list));

	new_slab->base = set_slab_base_addr(addr, new_slab);	
	//printf("slab base: 0x%x\n", new_slab->base);
	new_slab->base = fix_slab_base_addr(new_slab->base, 
		slab_cache->color_next);
	//printf("slab base: 0x%x\n", new_slab->base);
}

void *get_new_page(int order, int flag)
{
	void *mem = NULL;

	switch (flag) {
	case MEM_ALLOC_MMAP:
		break;
	case MEM_ALLOC_GLIBC:
		mem = malloc(PAGE_SIZE * (1 << order));
		break;
	default:
		return NULL;
	}

	return mem;
}

void *free_page(int flag, void *addr)
{
	switch (flag) {
	case MEM_ALLOC_MMAP:
		break;
	case MEM_ALLOC_GLIBC:
		free(addr);
		break;
	default:
		return ;
	}

	return ;
}

int init_slab(struct slab_cache *slab_cache, int size)
{
	int i;

	for (i = 0; i < SLAB_NUM; i++) {
		void *addr;

		addr = get_new_page(0, MEM_ALLOC_GLIBC);
		if (!addr) {
			fprintf(stderr, "alloc page failed.\n");
			return -1;
		}

		__init_slab(slab_cache, addr, size);
	}	

	return 0;
}

void init_general_slab_cache(struct thread_mem *thread_mem)
{
	int i;

	for (i = 0; i < thread_mem->slab_cache_array_size; i++) {
		//thread_mem->slab_cache_array[i].obj_cache = 
		(thread_mem->slab_cache_array + i)->obj_cache = 
			(struct slab_obj_cache *)malloc(sizeof(struct slab_obj_cache));
		if (!thread_mem->slab_cache_array[i].obj_cache) {
			fprintf(stderr, "alloc obj cache failed.\n");
			exit(-1);
		}
		thread_mem->slab_cache_array[i].slab_size = slab_size[i];
		thread_mem->slab_cache_array[i].slab_num = SLAB_NUM;
		thread_mem->slab_cache_array[i].free_num = 0;
		thread_mem->slab_cache_array[i].ctor = NULL;
		thread_mem->slab_cache_array[i].dtor = NULL;
		thread_mem->slab_cache_array[i].color_num = 
			compute_slab_color_num(slab_size[i], PAGE_SIZE);
        	thread_mem->slab_cache_array[i].color_next = -1;
		thread_mem->slab_cache_array[i].thread = thread_mem;
		INIT_LIST_HEAD(&(thread_mem->slab_cache_array[i].list));
		INIT_LIST_HEAD(&(thread_mem->slab_cache_array[i].cache_list));
		if (init_slab(&(thread_mem->slab_cache_array[i]), slab_size[i]) == -1)
			exit(-1);
	}
	fprintf(stdout, "Init genernal slab cache ok.\n");
}

void *kmem_cache_alloc(struct slab_cache *slab_cache)
{
	struct slab *s = NULL;
	struct list_head *p = NULL;
	void *obj = NULL;

	assert(slab_cache != NULL);

	pthread_mutex_lock(&(slab_cache->thread->slab_lock));
	if (!slab_cache->free_num) {
		if (!(s = expand_slab(slab_cache))) {
			fprintf(stderr, "expand slab failed.\n");
			pthread_mutex_unlock(&(slab_cache->thread->slab_lock));
			return NULL;
		}
		printf("expand slab ok.\n");
		obj = get_slab_obj(s, slab_cache);
		pthread_mutex_unlock(&(slab_cache->thread->slab_lock));
		return obj;
	}

	if (list_empty(&(slab_cache->list))) {
		pthread_mutex_unlock(&(slab_cache->thread->slab_lock));
		return NULL;
	}

	list_for_each(p, (&(slab_cache->list))) {
		s = list_entry(p, struct slab, list);
		if (s && s->free_num) {
			obj = get_slab_obj(s, slab_cache);
			pthread_mutex_unlock(&(slab_cache->thread->slab_lock));
			return obj;
		}
	}
	pthread_mutex_unlock(&(slab_cache->thread->slab_lock));

	return NULL;
}

struct slab_cache *search_slab_cache(struct thread_mem *thread_mem, char *name)
{
	struct slab_cache *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, (&(thread_mem->kmem_list_head))) {
		s = list_entry(p, struct slab_cache, cache_list);
		if (s && !strcmp(name, s->name))
			return s;
	}

	return NULL;
}

struct slab_cache *kmem_cache_create(struct thread_mem *thread_mem, 
		char *name, int size)
{
	struct slab_cache *cachep;
	int algin_size;

	assert(thread_mem != NULL);

	if (search_slab_cache(thread_mem, name))
		return NULL;

	cachep = (struct slab_cache *)kmem_cache_alloc(thread_mem->kmem_cache_st);
	if (!cachep) {
		fprintf(stderr, "create kmem cache failed.\n");
		return NULL;
	}
	fprintf(stdout, "kmem cache alloc at 0x%x\n", cachep);

	cachep->slab_size = ALIGN(size, DEFAULT_ALIGN);
	cachep->slab_num = SLAB_NUM;
	cachep->free_num = 0;
	cachep->ctor = NULL;
	cachep->dtor = NULL;
	cachep->thread = thread_mem;

	strcpy(cachep->name, name);

	INIT_LIST_HEAD(&(cachep->list));
	init_slab(cachep, cachep->slab_size);
	list_add_tail(&(cachep->cache_list), &(thread_mem->kmem_list_head));

	return cachep;
}

void kmem_cache_free(struct slab_cache *slab_cache, void *addr)
{
	struct slab *slab = NULL;
	struct list_head *p = NULL;
	
	if (!slab_cache || !addr)
		return ;

	pthread_mutex_lock(&(slab_cache->thread->slab_lock));
	slab = search_slab(addr, (&(slab_cache->list)));
	if (!slab) {
		printf("not found slab.\n");
		pthread_mutex_unlock(&(slab_cache->thread->slab_lock));
		return ;
	}
	//printf("found slab.\n");

	put_slab_obj(slab, addr, slab_cache);
	pthread_mutex_unlock(&(slab_cache->thread->slab_lock));
}

#define __FREE_LIST(type, link_head, flag) {                  	\
        type *p = NULL;                                         \
        struct list_head *s = NULL;                             \
        struct list_head *q = NULL;                             \
        for (s = (&link_head)->next; s != &link_head; s = q) {  \
                if (!s)                                         \
                        return ;                                \
                q = s->next;                                    \
                p = list_entry(s, type, list);                  \
                if (p) {                                        \
                        list_del(s);                            \
                        free_page(flag, p);          \
                        p = NULL;                               \
                }                                               \
        }}

void free_slab(struct slab_cache *slab_cache)
{
	__FREE_LIST(struct slab, slab_cache->list, MEM_ALLOC_GLIBC)
}

void free_slab_cache(struct thread_mem *thread_mem)
{
	__FREE_LIST(struct slab_cache, thread_mem->kmem_list_head, MEM_ALLOC_GLIBC)
}

void kmem_cache_destroy(struct thread_mem *thread_mem, struct slab_cache *slab_cache)
{
	free_slab(slab_cache);
	free_page(MEM_ALLOC_GLIBC, (void *)slab_cache->obj_cache);
	kmem_cache_free(thread_mem->kmem_cache_st, (void *)slab_cache);
}

void print_kmem_cache_list(struct thread_mem *thread_mem)
{
	struct slab_cache *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, (&(thread_mem->kmem_list_head))) {
		s = list_entry(p, struct slab_cache, cache_list);
		if (s) {
			printf("cache name: %s slab size: %d slab num: %d "
				"free num: %d color num: %d\n",
				s->name, s->slab_size, s->slab_num, 
				s->free_num, s->color_num); 
			__show_slab_list(&(s->list));
		}
	}
}

void init_kmem_cache(struct thread_mem *thread_mem)
{
	thread_mem->kmem_cache_st->slab_size = SLAB_CACHE_SIZE;
	thread_mem->kmem_cache_st->slab_num = SLAB_NUM;
	thread_mem->kmem_cache_st->free_num = 0;
	thread_mem->kmem_cache_st->ctor = NULL;
	thread_mem->kmem_cache_st->dtor = NULL;
	thread_mem->kmem_cache_st->thread = thread_mem;

	strcpy(thread_mem->kmem_cache_st->name, "kmem_cache_st");

	INIT_LIST_HEAD(&(thread_mem->kmem_cache_st->list));
	init_slab(thread_mem->kmem_cache_st, SLAB_CACHE_SIZE);
	list_add_tail(&(thread_mem->kmem_cache_st->cache_list), 
		&(thread_mem->kmem_list_head));

	printf("Init kmem cache ok.\n");
}

struct thread_mem *mem_cache_init(LIBEVENT_THREAD *thread, int array_size)
{
	struct thread_mem *thread_mem = NULL;

	thread_mem = (struct thread_mem *)malloc(sizeof(struct thread_mem));
	if (!thread_mem) {
		fprintf(stderr, "Malloc failed %d.\n", __LINE__);
		exit(-1);
	}
	thread_mem->slab_cache_array_size = array_size;

	thread_mem->slab_cache_array = (struct slab_cache *)
			malloc(sizeof(struct slab_cache) * array_size);
	if (!thread_mem->slab_cache_array) {
		fprintf(stderr, "Malloc failed %d.\n", __LINE__);
		exit(-1);
	}
	
	thread_mem->kmem_cache_st = (struct slab_cache *)malloc(sizeof(struct slab_cache));
	if (!thread_mem->kmem_cache_st) {
		fprintf(stderr, "Malloc failed %d.\n", __LINE__);
		exit(-1);
	}

	INIT_LIST_HEAD(&(thread_mem->kmem_list_head));
	pthread_mutex_init(&(thread_mem->slab_lock), NULL);
	list_add_tail(&(thread_mem->list), &thread_mem_list_head);

	thread_mem->thread = thread;

	init_general_slab_cache(thread_mem);
	init_kmem_cache(thread_mem);

	return thread_mem;
}

void mem_cache_destroy(struct thread_mem *thread_mem)
{
	//kmem_cache_destroy(thread_mem);

	free(thread_mem);
}
