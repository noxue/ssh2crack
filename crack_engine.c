/*
 * Crack_engine.c 
 * 	
 * Crack engine is a thread pool that schedule threads to call 
 * certain crack module.
 *
 * 2012 by wzt (c)	http://www.cloud-sec.org
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include "list.h"
#include "slab.h"
#include "ssh2crack.h"
#include "thread_pool.h"
#include "debug.h"

extern struct thread_mem *main_thread_mem;
extern struct slab_cache *user_cache, *host_cache, *worker_cache;

THREAD_POOL *thread_pool = NULL;
pthread_mutex_t list_lock;
pthread_mutex_t init_lock;
pthread_cond_t init_cond;
int init_count = 0;

int add_all_worker_flag = 0;
int crack_match_flag = 0;
int count_play = 0;
int current_job = 0;
char *play[5] = {"|", "/", "-", "\\", NULL};

/**
 * Create thread pool and start it.
 */
int init_thread_pool(int thread_num)
{
	int thread_idx;

	thread_pool = (THREAD_POOL *)malloc(sizeof(THREAD_POOL));
	if (!thread_pool) {
		fprintf(stderr, "Malloc failed.\n");
		return -1;
	}

	thread_pool->thread_id =  
			(pthread_t *)malloc(sizeof(pthread_t) * thread_num);
	if (!thread_pool->thread_id) {
		fprintf(stderr, "Malloc failed.\n");
		goto free_thread_pool;
		return -1;
	}	

	pthread_mutex_init(&(thread_pool->queue_lock), NULL);
	pthread_mutex_init(&init_lock, NULL);
	pthread_cond_init(&(thread_pool->queue_ready), NULL);
	pthread_cond_init(&init_cond, NULL);

	INIT_LIST_HEAD(&(thread_pool->worker_list_head));
	thread_pool->destroy_flag = 0;
	thread_pool->max_thread_num = thread_num;
	thread_pool->curr_worker_num = 0;

	for (thread_idx = 0; thread_idx < thread_num; thread_idx++) {
		if (pthread_create(&(thread_pool->thread_id[thread_idx]), NULL,
			worker_thread, NULL) != 0) {
			perror("pthread_create");
			goto free_thread;
		}
		//fprintf(stderr, "[+] Create thread %d ok.\n", thread_idx);
	}

/*
	pthread_mutex_lock(&init_lock);
	while (init_count < thread_num)
		pthread_cond_wait(&init_cond, &init_lock);
	phtread_mutex_unlock(&init_lock);
*/

	return 0;

free_thread:
	for (; thread_idx > 0; thread_idx--)
		pthread_cancel(thread_idx);
free_thread_id:
	free(thread_pool->thread_id);
free_thread_pool:
	free(thread_pool);

	return -1;
}

THREAD_WORKER *alloc_worker_node(void)
{
	THREAD_WORKER *new_worker = NULL;

#ifdef SLAB
	new_worker = (THREAD_WORKER *)kmem_cache_alloc(worker_cache);
	if (!new_worker) {
		fprintf(stderr, "Malloc failed.\n");
		return NULL;
	}
#else
	new_worker = (THREAD_WORKER *)malloc(sizeof(THREAD_WORKER));
	if (!new_worker) {
		fprintf(stderr, "Malloc failed.\n");
		return NULL;
	}
#endif
	memset((void *)new_worker, '\0', sizeof(THREAD_WORKER));

	return new_worker;
}

void free_worker(THREAD_WORKER *worker)
{
#ifdef SLAB
	kmem_cache_free(worker_cache, (void *)worker);
#else
	free(worker);
#endif
}

/**
 * push a worker to wait queue.
 */
int push_worker(crack_fn fn, CRACK_HOST *host_p, CRACK_USER *user_p, char *ip, 
		unsigned int port, char *user, char *passwd)
{
	THREAD_WORKER *new_worker = NULL;

	new_worker = alloc_worker_node();
	if (!new_worker)
		return -1;

	new_worker->do_crack = fn;
	new_worker->crack_host = host_p;
	new_worker->crack_user = user_p;
	new_worker->port = port;
	strcpy(new_worker->ip, ip);
	strcpy(new_worker->user, user);
	strcpy(new_worker->passwd, passwd);

	/* add to wait queue list. */
	pthread_mutex_lock(&(thread_pool->queue_lock));
	list_add(&(new_worker->list), &(thread_pool->worker_list_head));
	thread_pool->curr_worker_num++;
	pthread_mutex_unlock(&(thread_pool->queue_lock));

	pthread_cond_signal(&(thread_pool->queue_ready));

	return 0;
}

THREAD_WORKER *pop_worker(struct list_head *list_head)
{
	THREAD_WORKER *worker = NULL;
	struct list_head *p = NULL;

	worker = list_entry(list_head->next, THREAD_WORKER, list);		
	if (!worker)
		return NULL;

	list_del(list_head->next);
	return worker;
}

void print_worker_list(void)
{
	THREAD_WORKER *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, ((&(thread_pool->worker_list_head)))) {
		s = list_entry(p, THREAD_WORKER, list);
		if (s) {
			fprintf(stderr, "[*] %s, %d\n", s->ip, s->port);
		}
	}
}

void show_result(THREAD_WORKER *worker, int value)
{
	char buff[1024];

	if (count_play == 4)
		count_play = 0;

	if (!value) {
		snprintf(buff, sizeof(buff), " %s %5d/%-5d %2.2f%%\tCracking %-24s [%-16s]\t[%-16s]\t[success]\n",
			play[count_play++], current_job,
			host_opt->len * user_opt->len * passwd_opt->len,
			(float)(current_job) / (float)(host_opt->len * user_opt->len * passwd_opt->len),
			worker->ip, worker->user, worker->passwd);
		write(1, buff, strlen(buff));
		pthread_mutex_lock(&(thread_pool->queue_lock));
		fputs(buff, result_fp);
		pthread_mutex_unlock(&(thread_pool->queue_lock));
	}
	else {
		snprintf(buff, 1024, " %s %5d/%-5d %2.2f%%\tCracking %-24s [%-16s]\t[%-16s]\t[Failed]\r",
			play[count_play++], current_job, 
			host_opt->len * user_opt->len * passwd_opt->len,
			(float)(current_job) / (float)(host_opt->len * user_opt->len * passwd_opt->len),
			worker->ip, worker->user, worker->passwd);
		write(1, buff, strlen(buff));
	}
}

void *worker_thread(void *arg)
{
	THREAD_WORKER *worker = NULL;
	int ret = -1;

	for (;;) {
		/* Get the lock and try to check the current
  		 * queue num is not NULL. */
		pthread_mutex_lock(&(thread_pool->queue_lock));
		while (!thread_pool->curr_worker_num &&
			!thread_pool->destroy_flag) {
			pthread_cond_wait(&(thread_pool->queue_ready),
				&(thread_pool->queue_lock));
		}

		/* Start to destroy thread pool */
		if (thread_pool->destroy_flag == 1) {
			pthread_mutex_unlock(&(thread_pool->queue_lock));
			break;
		}

		/* Get a worker from the queue. */
		worker = pop_worker((&(thread_pool->worker_list_head)));
		if (!worker) {
			pthread_mutex_unlock(&(thread_pool->queue_lock));
			continue;
		}
			
		thread_pool->curr_worker_num--;
		current_job++;
		pthread_mutex_unlock(&(thread_pool->queue_lock));

		if (worker->do_crack) {
			/* match the user map first. */
			pthread_mutex_lock(&(thread_pool->queue_lock));
			if (!worker->crack_host->user_map[worker->crack_user->index]) {
				pthread_mutex_unlock(&(thread_pool->queue_lock));
				ret = worker->do_crack(worker->ip, worker->port, ssh2crack_arg->timeout, 
						worker->user, worker->passwd);
				if (!ret) {
					/* Target match the passwd, set the user map. */
					pthread_mutex_lock(&(thread_pool->queue_lock));
					worker->crack_host->user_map[worker->crack_user->index] = 1;
					pthread_mutex_unlock(&(thread_pool->queue_lock));
				}
				show_result(worker, ret);
			}
			else {
				pthread_mutex_unlock(&(thread_pool->queue_lock));
			}
			free_worker(worker);
		}
		worker = NULL;
	}
}

int destroy_thread_pool(void)
{
	int thread_idx;

	/* set the destroy flag. */
	pthread_mutex_lock(&(thread_pool->queue_lock));
	thread_pool->destroy_flag = 1;
	pthread_mutex_unlock(&(thread_pool->queue_lock));

	/* call all wait threads. */
	pthread_cond_broadcast(&(thread_pool->queue_ready));

	/* wait threads to finsh. */
	for (thread_idx = 0; thread_idx < thread_pool->max_thread_num; 
			thread_idx++) {
		if (pthread_join(thread_pool->thread_id[thread_idx], NULL) != 0) {
			perror("thread_join");
			return 0;
		}
		//fprintf(stderr, "[+] Join thread %d ok.\n", thread_idx);
	}
	
	pthread_mutex_destroy(&(thread_pool->queue_lock));
	pthread_cond_destroy(&(thread_pool->queue_ready));

	FREE_LIST(THREAD_WORKER, (thread_pool->worker_list_head))

	thread_pool = NULL;
	fprintf(stderr, "\n\nWait all threads ok.\n");

	return 1;
}

void wait_all_thread_finsh(void)
{
	for (;;) {
		pthread_mutex_lock(&(thread_pool->queue_lock));
		if ((thread_pool->curr_worker_num == 0 &&
			add_all_worker_flag == 1) || (crack_match_flag == 1)) {
			pthread_mutex_unlock(&(thread_pool->queue_lock));
			destroy_thread_pool();
			break;
		}
		pthread_mutex_unlock(&(thread_pool->queue_lock));
		usleep(20);
	}
}

void test_queue_num(void)
{
	for (;;) {
		pthread_mutex_lock(&(thread_pool->queue_lock));
		if (thread_pool->curr_worker_num == MAX_QUEUE_NUM) {
			pthread_mutex_unlock(&(thread_pool->queue_lock));
			usleep(30);
		}
		pthread_mutex_unlock(&(thread_pool->queue_lock));
		break;
	}
}

int check_host_status(CRACK_HOST *host_p)
{
	pthread_mutex_lock(&(thread_pool->queue_lock));
	if (host_p->current_user >= host_p->total_user) {
		pthread_mutex_unlock(&(thread_pool->queue_lock));
		return 0;
	}

	pthread_mutex_unlock(&(thread_pool->queue_lock));
	return -1;
}

/**
 * Add all scan ip and ports to the wait queue.
 */
void *add_all_worker_thread(void *arg)
{
	CRACK_HOST *host_s = NULL;
	CRACK_USER *user_s = NULL; 
	CRACK_PASSWD *passwd_s = NULL;
	struct list_head *host_p = NULL;
	struct list_head *user_p = NULL;
	struct list_head *passwd_p = NULL;

	/* list all host node. */
	list_for_each(host_p, (&(host_opt->list_head))) {
		host_s = list_entry(host_p, CRACK_HOST, list);
		if (host_s) {
			/* list all user node. */
			list_for_each(user_p, (&(user_opt->list_head))) {
				user_s = list_entry(user_p, CRACK_USER, list);
				if (user_s) {
					/* list all passwd node. */
					list_for_each(passwd_p, (&(passwd_opt->list_head))) {
						passwd_s = list_entry(passwd_p, CRACK_PASSWD, list);
						if (passwd_s) {
							test_queue_num();
							/* add it to worker queue. */
							push_worker(ssh2_connect, host_s, user_s, 
								host_s->data, SSH_PORT, 
								user_s->data, passwd_s->data);
						}
					}
				}
			}
		}
	}

	/* This flag is very important. The destroy thread will use it. */
	add_all_worker_flag = 1;
	//fprintf(stderr, "[+] Add all worker finshed.\n");
}

int start_add_worker_thread(void)
{
	pthread_t id;

	if (pthread_create(&id, NULL, add_all_worker_thread, NULL) != 0) {
		perror("thread_create");
		return -1;
	}
	//fprintf(stderr, "[+] Start add worker thread ok.\n");

	return 0;
}

void handle_sigint(int sig)
{
	crack_match_flag = 1;
}
