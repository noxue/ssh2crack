#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAXUSER         100

unsigned int make_network_ip(char *host);
int tcp_connect(unsigned int remote_ip, unsigned int remote_port);
int tcp_connect_timeout(unsigned int remote_ip, unsigned int remote_port, 
	struct timeval timeout);
int tcp_connect_nblock(unsigned int remote_ip,
                unsigned int remote_port, int timeout);
int tcp_connect_fast(unsigned int remote_ip,
                unsigned int remote_port, int timeout);
int bind_sock(unsigned int port);
int get_ip_of_domain(char *domain, char *ip_addr);
int get_ip_of_domain_safe(char *domain, char *ip_addr);

#endif	/* _SOCKET_H_ */

