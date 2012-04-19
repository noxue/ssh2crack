#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include "list.h"
#include "ssh2crack.h"

#define MAX_THREAD_NUM		5
#define MAX_QUEUE_NUM		200

typedef struct thread_worker_st {
	int (*do_crack)(char *, unsigned int, unsigned int, char *, char *);
	char ip[64];
	unsigned int port;
	char user[64];
	char passwd[64];
	struct list_head list;
	CRACK_HOST *crack_host;
	CRACK_USER *crack_user;
}THREAD_WORKER;

typedef struct thread_pool_st {
	pthread_t *thread_id;
	pthread_mutex_t queue_lock;
	pthread_cond_t queue_ready;
	struct list_head worker_list_head;
	int destroy_flag;
	int max_thread_num;
	int curr_worker_num;
}THREAD_POOL;

int init_thread_pool(int thread_num);
int add_worker(int (*fn)(char *ip, unsigned int, unsigned int, char*, char *),
		CRACK_HOST *host_p, CRACK_USER *user_p, char *ip, 
		unsigned int port, char *user, char *passwd);
void print_worker_list(void);
void *worker_thread(void *arg);
int destroy_thread_pool(void);
void wait_all_thread_finsh(void);
void *add_all_worker_thread(void *arg);
int start_add_worker_thread(void);
void handle_sigint(int sig);

#endif
