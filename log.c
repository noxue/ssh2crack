/*
 * log.c (c) 2012 wzt 	http://www.cloud-sec.org
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>

#include "log.h"

static LOG_ARG *log_arg = NULL;

int log_init(void)
{
	char buff[1024];

	log_arg = (LOG_ARG *)malloc(sizeof(LOG_ARG));
	if (!log_arg) {
		fprintf(stderr, "Malloc failed.\n");
		return -1;
	}

	log_arg->log_level = LOG_DEBUG2;
	log_arg->log_file_num = 10;
	log_arg->log_size = 2 * 1024 * 1024;
	strcpy(log_arg->log_path, "/var/log/ssh2crack");
	pthread_mutex_init(&log_arg->log_lock, NULL);

	mkdir(log_arg->log_path, 700);

	snprintf(buff, sizeof(buff), "%s/log.1", log_arg->log_path);
	strcpy(log_arg->curr_log, buff);

	log_lock();
	log_arg->log_fp = fopen(buff, "w+");
	if (!log_arg->log_fp) {
		perror("fopen");
		log_unlock();
		free(log_arg);
		return -1;
	}
	log_unlock();

	return 0;
}

int extract_log_num(void)
{
	char *s = log_arg->curr_log;
	char tmp[4];

	assert(s != NULL);

	while (*s++);
	s--;
	printf("!%c\n", *s);

	while (*s-- != '.')
	printf("!%c\n", *s);

	strcpy(tmp, s);
	printf("!%s\n", tmp);

	return atoi(tmp);
}

int expand_log(void)
{
	int log_num;
	char buff[1024];

	log_num = extract_log_num();
	if (log_num > log_arg->log_file_num - 1)
		return -1;

	log_lock();
	fclose(log_arg->log_fp);
	snprintf(buff, sizeof(buff), "%s/log.%d", log_arg->log_path, log_num + 1);
	log_arg->log_fp = fopen(buff, "w+");
	if (!log_arg->log_fp) {
		perror("fopen");
		log_unlock();
		free(log_arg);
		return -1;
	}

	log_unlock();
	return 0;
}

int check_log_size(void)
{
	struct stat f_stat;

	log_lock();
	if (stat(log_arg->curr_log, &f_stat) == -1) {
		perror("stat");
		log_unlock();
		return -1;
	}

	if (f_stat.st_size >= log_arg->log_size) {
		if (expand_log() == -1) {
			log_unlock();
			return -1;
		}
	}

	log_unlock();
	return 0;
}

void do_log(LOG_LEVEL log_level, int flag, char *file_name, int line,
		va_list args, char *fmt)
{
	struct tm *log_now;
	time_t log_t;
	char buff[1024];

	assert(log_arg->log_level != LOG_NOLEVEL);

	if (log_level < log_arg->log_level)
		return ;

	time(&log_t);
	log_now = localtime(&log_t);
	snprintf(buff, sizeof(buff), 
		"%04d-%02d-%02d %02d:%02d:%02d -- %s(%d):\t",
		log_now->tm_year + 1900, log_now->tm_mon + 1, 
		log_now->tm_mday, log_now->tm_hour, log_now->tm_min, 
		log_now->tm_sec, file_name, line);
	vsprintf(buff + strlen(buff), fmt, args);

	if (flag == LOG_STDOUT) {
		fprintf(stdout, "%s\n", buff);
		return ;
	}

	if (check_log_size() == -1)
		return ;

	log_lock();
	fprintf(log_arg->log_fp, "%s", buff);
	log_unlock();
}

void debug(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_DEBUG, LOG_FILE, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void __debug(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_DEBUG, LOG_STDOUT, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void debug1(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_DEBUG1, LOG_FILE, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void __debug1(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_DEBUG1, LOG_STDOUT, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void debug2(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_DEBUG2, LOG_FILE, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void __debug2(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_DEBUG2, LOG_STDOUT, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void fatal(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_FATAL, LOG_FILE, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void __fatal(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_FATAL, LOG_STDOUT, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void error(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_ERROR, LOG_FILE, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void __error(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_ERROR, LOG_STDOUT, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void info(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_INFO, LOG_FILE, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void __info(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	do_log(LOG_INFO, LOG_STDOUT, __FILE__, __LINE__, args, fmt);
	va_end(args);
}

void log_close(void)
{
	log_lock();
	fclose(log_arg->log_fp);
	log_unlock();
}

void log_destroy(void)
{
	log_close();
	pthread_mutex_destroy(&log_arg->log_lock);
	free(log_arg);
}

void log_lock(void)
{
	pthread_mutex_lock(&log_arg->log_lock);
}

void log_unlock(void)
{
	pthread_mutex_unlock(&log_arg->log_lock);
}
