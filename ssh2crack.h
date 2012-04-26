#ifndef SSH2CRACK_H
#define SSH2CRACK_H

#include "list.h"

#define SLAB

#define SSH2CRACK_BANNER	"SSH2CRACK"
#define SSH2CRACK_VERSION	"v0.08"
#define SSH2CRACK_AUTHOR	"Copyright (c) wzt 2008-2012"
#define SSH2CRACK_DESC		"SSH Remote Passwd Crack Tool"

#define SSH_PORT		22

#define DEFAULT_TIMEOUT		5
#define DEFAULT_THREAD_NUM	5
#define DEFAULT_DAEMON_STATUS	0
#define DEFAULT_LOG		"log"

enum ssh2_opt{
	SSH2_USER,
	SSH2_HOST,
	SSH2_PASSWD
};

typedef struct ssh2crack_arg {
	char user[64];
	char user_list[128];
	char host[64];
	char host_list[128];
	char passwd[64];
	char passwd_list[128];
	char log[128];
	unsigned int timeout;
	unsigned int thread_num;
	unsigned int daemon;
}SSH2CRACK_ARG;

typedef struct crack_user_st {
	char data[64];
	int index;
	struct list_head list;
}CRACK_USER;

typedef struct crack_host_st {
	unsigned int *user_map;
	int total_user;
	int current_user;
	char data[64];
	struct list_head list;
}CRACK_HOST;

typedef struct crack_passwd_st {
	char data[64];
	int index;
	struct list_head list;
}CRACK_PASSWD;

typedef struct ssh2crack_opt {
	int status;
	int len;
	struct list_head list_head;
}SSH2CRACK_OPT;

typedef int (*crack_fn)(char *, unsigned int, unsigned int, char*, char *);

typedef struct crack_module {
	char name[64];
	unsigned int timeout;
	unsigned int port;
	crack_fn crack_cb;
	struct list_head list;
}CRACK_MODULE;

typedef struct crack_module_mnt {
	int module_num;
	struct list_head list_head;
}CRACK_MODULE_MNT;

SSH2CRACK_ARG *ssh2crack_arg;
SSH2CRACK_OPT *user_opt, *host_opt, *passwd_opt;
CRACK_MODULE_MNT *crack_module_mnt;
pthread_mutex_t file_lock;

FILE *result_fp;
int ssh2_connect(char *ip, unsigned int port, unsigned int timeout, 
		char *user, char *passwd);

#endif
