#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <pthread.h>

typedef enum {
	LOG_FATAL,
	LOG_ERROR,
	LOG_INFO,
	LOG_DEBUG,
	LOG_DEBUG1,
	LOG_DEBUG2,
	LOG_NOLEVEL
}LOG_LEVEL;

enum {
	LOG_STDOUT,
	LOG_FILE
};

typedef struct log_arg {
	int log_level;
	int log_file_num;
	int log_size;
	char log_path[1024];
	char curr_log[1024];
	FILE *log_fp;
	pthread_mutex_t log_lock;
}LOG_ARG;

void log_lock(void);
void log_unlock(void);

void debug(char *fmt, ...);
void __debug(char *fmt, ...);
void debug1(char *fmt, ...);
void __debug1(char *fmt, ...);
void debug2(char *fmt, ...);
void __debug2(char *fmt, ...);
void fatal(char *fmt, ...);
void __fatal(char *fmt, ...);
void error(char *fmt, ...);
void __error(char *fmt, ...);
void info(char *fmt, ...);
void __info(char *fmt, ...);

#endif
