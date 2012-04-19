#ifndef DEBUG_H
#define DEBUG_H

#define DEBUG                   1

#if DEBUG == 1
#define DbgPrint(mesg, ...)     fprintf(stderr, mesg, __VA_ARGS__)
#else
#define DbgPrint(mesg, ...)
#endif

#endif
