#ifndef SLAB_H
#define SLAB_H

#include <pthread.h>
#include "list.h"

#define SLAB_SIZE_NUM				9
#define SLAB_NUM				2
#define SLAB_MAX_OBJ				PAGE_SIZE / 8

#define SLAB_CACHE_NAME_LEN			16

struct slab_obj_cache {
	unsigned int curr_obj;
	unsigned int limit;
	void *entry;
};

struct slab_cache {
	struct slab_obj_cache *obj_cache;
	int slab_size;
	int slab_num;
	int free_num;
	int align;
	int color_num;
	int color_next;
	char name[SLAB_CACHE_NAME_LEN];
	void (*ctor)(void);
	void (*dtor)(void);
	struct list_head list;			/* slab list head */
	struct list_head cache_list;		/* slab cache list */
	struct thread_mem *thread;		/* thread_mem belong to */
};

struct slab {
	int obj_num;
	int free_num;
	int free_idx;
	void *base;
	struct list_head list;
};

typedef struct thread {
	unsigned int whatever;
}LIBEVENT_THREAD;

struct thread_mem {
	struct slab_cache *slab_cache_array;
	int slab_cache_array_size;
	struct slab_cache *kmem_cache_st;
	struct list_head kmem_list_head;
	LIBEVENT_THREAD *thread;
	pthread_mutex_t slab_lock;
	struct list_head list;
};

#define SLAB_CACHE_SIZE		sizeof(struct slab_cache)
#define SLAB_SIZE		sizeof(struct slab)

#define ALIGN(x, a)             (((x) + (a - 1)) & (~(a - 1)))
#define DEFAULT_ALIGN		4

#define MEM_ALLOC_MMAP		0
#define MEM_ALLOC_GLIBC		1
#define PAGE_SIZE		4096
#define PAGE_ORDER_ZERO		0

struct list_head thread_mem_list_head;

void *get_new_page(int order, int flag);
void init_kmem_cache(struct thread_mem *thread_mem);
void *slab_alloc(struct thread_mem *thread_mem, int size);
void slab_free(struct thread_mem *thread_mem, void *addr, int size);
void init_general_slab_cache(struct thread_mem *thread_mem);
void *kmem_cache_alloc(struct slab_cache *slab_cache);
struct slab_cache *kmem_cache_create(struct thread_mem *thread_mem,
                char *name, int size);
void kmem_cache_free(struct slab_cache *slab_cache, void *addr);
void kmem_cache_destroy(struct thread_mem *thread_mem, struct slab_cache *slab_cache);
struct thread_mem *mem_cache_init(LIBEVENT_THREAD *thread, int array_size);

#endif
