/* 
 * Copyright (c) wzt 2008 - 2012
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>

#include "libsock.h"

/**
 * make_network_ip - make ip from host byte to network byte.
 *
 * host - remote host ip.
 *
 * successfull return the network byte,failed return 0;
 */
unsigned int make_network_ip(char *host)
{
        struct hostent *h;
        unsigned int ret;

        if ((h = gethostbyname(host)) == NULL) {
                ret = inet_addr(host);
                if (ret == -1)
                        return 0;
                return ret;
        }
        else {
                ret = *((unsigned int *)h->h_addr);
                if (ret <= 0)
                        return 0;
                return ret;
        }
}

int get_ip_of_domain(char *domain, char *ip_addr)
{
	struct hostent ret, *host;
	char buff[8192];
	int i, h_err;

	if ((host = gethostbyname(domain)) != NULL)
		return 0;

	for (i = 0; host->h_addr_list[i] != NULL; i++) {
		if (inet_ntop(AF_INET, host->h_addr_list[i], ip_addr,
					sizeof(ip_addr)) != NULL) {
			return 1;
		}
	}
						 
	return 0;
}

int get_ip_of_domain_safe(char *domain, char *ip_addr)
{
	struct hostent ret, *host;
	char buff[8192];
	int i, h_err;

	if (gethostbyname_r(domain, &ret, buff, 8192, &host, &h_err) != 0)
		return 0;

	for (i = 0; host->h_addr_list[i] != NULL; i++) {
		if (inet_ntop(AF_INET, host->h_addr_list[i], ip_addr, 
			sizeof(ip_addr)) != NULL) {
			return 1;
		}
	}

	return 0;
}

/* read n bytes from a file descriptor. */
ssize_t sock_readn(int sock_id, char *ptr, size_t n)
{
	size_t n_left;
	ssize_t n_read;

	n_left = n;
	while (n_left > 0) {
		if ((n_read = read(sock_id, ptr, n_left)) < 0) {
			if (errno == EINTR)
				continue;
			if (n_left == n)
				return -1;
			else
				break;
		}
		else if (n_read == 0)
			break;
		n_left -= n_read;
		ptr += n_read;
	}

	return n - n_left;
}
				
/* write n bytes to a file descriptor. */
ssize_t sock_writen(int sock_id, char *ptr, size_t n)
{
        size_t n_left;
        ssize_t n_written;

        n_left = n;
        while (n_left > 0) {
                if ((n_written = write(sock_id, ptr, n_left)) < 0) {
                        if (errno == EINTR)
                                continue;
                        if (n_left == n)
                                return -1;
                        else
                                break;
                }
                else if (n_written == 0)
                        break;
                n_left -= n_written;
                ptr += n_written;
        }

        return n - n_left;
}


ssize_t sock_read_timeout(int sock_id, char *buff, size_t n, int time_out)
{
	fd_set readfds;
	struct timeval timeout;
        size_t n_left;
        ssize_t n_read = 0;
	int ret;

        while (1) {
	        FD_ZERO(&readfds);
        	FD_SET(sock_id, &readfds);

        	timeout.tv_sec = time_out;
        	timeout.tv_usec = 0;

		ret = select(sock_id + 1, &readfds, NULL, NULL, &timeout);
		if (ret < 0) {
			perror("select:\n");
			if (errno == EINTR)
				continue;
			return -1;
		}

		if (ret == 0) {
			printf("%s", "select timeout.\n");
			return 0;
		}

		if (FD_ISSET(sock_id, &readfds)) {
                	if ((n_read = read(sock_id, buff, n)) < 0) {
				return -1;
                	}
			else
				break;
        	}
	}

        return n_read;
}

ssize_t sock_write_timeout(int sock_id, char *buff, size_t n, int time_out)
{
        fd_set writefds;
        struct timeval timeout;
        ssize_t n_written = 0;
        int ret;

        while (1) {
                FD_ZERO(&writefds);
                FD_SET(sock_id, &writefds);

                timeout.tv_sec = time_out;
                timeout.tv_usec = 0;

                ret = select(sock_id + 1, NULL, &writefds, NULL, &timeout);
                if (ret < 0) {
                        if (errno == EINTR)
                                continue;
                        return -1;
                }

                if (ret == 0) {
                        printf("%s", "select timeout.\n");
                        return 0;
                }

                if (FD_ISSET(sock_id, &writefds)) {
                        if ((n_written = write(sock_id, buff, n)) < 0) {
                                if (errno == EINTR)
                                        continue;
				return -1;
                        }
                        else
                                break;
                }
        }

        return n_written;
}

ssize_t sock_readn_timeout(int sock_id, char *ptr, size_t n, int time_out)
{
        fd_set readfds;
        struct timeval timeout;
        size_t n_left;
        ssize_t n_read;
        int ret;

        timeout.tv_sec = time_out;
        timeout.tv_usec = 0;

        n_left = n;
        while (n_left > 0) {
                FD_ZERO(&readfds);
                FD_SET(sock_id, &readfds);

                ret = select(sock_id + 1, &readfds, NULL, NULL, &timeout);
                if (ret < 0) {
                        if (errno == EINTR)
                                continue;
                        return n - n_left;
                }

                if (ret == 0) {
                        return n - n_left;
                }

                if (FD_ISSET(sock_id, &readfds)) {
                        if ((n_read = read(sock_id, ptr, n_left)) < 0) {
                                if (errno == EINTR)
                                        continue;
                                if (n_left == n)
                                        return -1;
                                else
                                        break;
                        }
                        else if (n_read == 0)
                                break;
                        n_left -= n_read;
                        ptr += n_read;
                }
        }

        return n - n_left;
}

ssize_t sock_writen_timeout(int sock_id, char *ptr, size_t n, int time_out)
{
        fd_set writefds;
        struct timeval timeout;
        size_t n_left;
        ssize_t n_written;
        int ret;

        timeout.tv_sec = time_out;
        timeout.tv_usec = 0;

        n_left = n;
        while (n_left > 0) {
        	FD_ZERO(&writefds);
        	FD_SET(sock_id, &writefds);

                ret = select(sock_id + 1, NULL, &writefds, NULL, &timeout);
                if (ret < 0) {
                        if (errno == EINTR)
                                continue;
                        return n - n_left;
                }

                if (ret == 0) {
                        return n - n_left;
                }

                if (FD_ISSET(sock_id, &writefds)) {
                        if ((n_written = write(sock_id, ptr, n_left)) < 0) {
                                if (errno == EINTR)
                                        continue;
                                if (n_left == n)
                                        return -1;
                                else
                                        break;
                        }
                        else if (n_written == 0)
                                break;
                        n_left -= n_written;
                        ptr += n_written;
                }
        }

        return n - n_left;
}

int tcp_connect(unsigned int remote_ip, unsigned int remote_port)
{
        struct sockaddr_in serv_addr;
        int sock_fd;

        if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                perror("[-] socket");
                return -1;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = remote_port;
        serv_addr.sin_addr.s_addr = remote_ip;

        if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr)) == -1) {
		close(sock_fd);
               	return -1;
	}

        return sock_fd;
}

int tcp_connect_timeout(unsigned int remote_ip, unsigned int remote_port, 
	struct timeval timeout)
{
	struct sockaddr_in serv_addr;
	int sock_fd;

	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("[-] socket");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = remote_port;
	serv_addr.sin_addr.s_addr = remote_ip;

	if (connect(sock_fd, (struct sockaddr *)&serv_addr, 
		sizeof(struct sockaddr)) == -1) {
		close(sock_fd);
	       	return -1;
	}

        if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, (void *)&timeout, 
		sizeof(timeout)) == -1) {
		perror("setsockopt.");
	}
        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout, 
		sizeof(timeout)) == -1) {
		perror("setsockopt.");
	}

        return sock_fd;
}

/**
 * tcp_connect_nblock - connect to remote host.
 *
 * ip: remote ip but with network byte.
 * port : remote port but with network byte.
 *
 * if connected successfull, return remote socket descriptor,failed return 0;
 */
int tcp_connect_nblock(unsigned int remote_ip, unsigned int remote_port, 
		int timeout)
{
	struct sockaddr_in serv_addr;
	struct timeval time_out;
	fd_set r_fds, w_fds;
	int sock_fd;
	unsigned long flag;
	int len, error;
	int ret;

	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = remote_port;
	serv_addr.sin_addr.s_addr = remote_ip;

        flag = fcntl(sock_fd, F_GETFL, 0);
        if (flag < 0) {
		perror("fcntl");
                goto err;
        }
        if (fcntl(sock_fd, F_SETFL, flag | O_NONBLOCK) < 0) {
		perror("fcntl");
                goto err;
        }

	ret = connect(sock_fd, (struct sockaddr *)&serv_addr, 
			sizeof(struct sockaddr));
	if (ret == -1) {
		if (errno != EINPROGRESS)
			goto err;
	}
	if (ret == 0)
		return sock_fd;

	time_out.tv_sec = timeout;
	time_out.tv_usec = 0;

	FD_ZERO(&w_fds);
	FD_SET(sock_fd, &w_fds);
	r_fds = w_fds;
	
	ret = select(sock_fd + 1, &r_fds, &w_fds, NULL, &time_out);
        if (ret <= 0) {
		goto err;
	}
        else {
               	if (FD_ISSET(sock_fd, &w_fds) || FD_ISSET(sock_fd, &r_fds)) {
                       	len = sizeof(error);
                        if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, 
				(char *)&error, &len) < 0)
                               	goto err;
                        if (error == 0) {
                               	if (fcntl(sock_fd, F_SETFL, flag) < 0) {
					perror("fcntl");
                                        goto err;
                                }
                                return sock_fd;
                        }
                        else {
                                goto err;
			}
                }
                else {
                      	goto err;
		}
        }

err:
        close(sock_fd);
        return -1;
}

/**
 * tcp_connect_fast - connect to remote host.
 *
 * the function like tcp_connect(),but when it connected successfull,it close
 * the socket immediately,do not read and write data.
 *
 * ip: remote ip but with network byte.
 * port : remote port but with network byte.
 *
 * if connected successfull ,return 1,failed return 0;
 */
int tcp_connect_fast(unsigned int remote_ip, unsigned int remote_port, 
	int timeout)
{
        struct sockaddr_in serv_addr;
        struct timeval time_out;
        fd_set w_fds;
        int sock_fd;
        unsigned long flag;
        int len, error;
        int ret;

        if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                printf("%s", "[-] socket\n");
                return -1;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = remote_port;
        serv_addr.sin_addr.s_addr = remote_ip;

        flag = fcntl(sock_fd, F_GETFL, 0);
        if (flag < 0) {
                printf("%s", "[-] get fcntl error.\n");
                goto err;
        }
        if (fcntl(sock_fd, F_SETFL, flag | O_NONBLOCK) < 0) {
                printf("%s", "[-] set fcntl error.\n");
                goto err;
        }

        if (connect(sock_fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr)) == -1) {
                if (errno != EINPROGRESS)
                        goto err;

                time_out.tv_sec = timeout;
                time_out.tv_usec = 0;

                FD_ZERO(&w_fds);
                FD_SET(sock_fd, &w_fds);

                ret = select(sock_fd + 1, NULL, &w_fds, NULL, &time_out);
                if (ret < 0) {
                        printf("%s", "select error.\n");
                        goto err;
                }
                else if (ret == 0) {
                        printf("%s", "select timeout.\n");
                        close(sock_fd);
                        return 0;
                }
                else {
                        if (FD_ISSET(sock_fd, &w_fds)) {
                                len = sizeof(error);
                                if (getsockopt(sock_fd, SOL_SOCKET,
                                        SO_ERROR, (char *)&error, &len) < 0)
                                        goto err;
                                if (error == 0) {
                                        close(sock_fd);
                                        return 1;
                                }
                                else
                                      goto err;
                        }
                        else
                                goto err;
                }
        }

        err:

        close(sock_fd);
        return -1;
}

/**
 * tcp_bind - bind a port with localhost.
 *
 * port : localport but with network byte.
 *
 * successfull return the remote socket descriptor,failed retrurn 0;
 */
int bind_sock(unsigned int port)
{
	struct sockaddr_in my_addr;
	int sock_fd;
	int reuse_flag = 1;

	if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("[-] socket");
		return -1;
	}

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = INADDR_ANY;

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse_flag, 
		sizeof(reuse_flag)) == -1) {
		perror("setsockopt.");
	}

	if (bind(sock_fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) < 0) {
		close(sock_fd);
		return -1;
	}

	return sock_fd;
}

int set_sock_keep_alive(int sock_fd, int keep_alive, int keep_idle, int keep_interval,
		int keep_count)
{

        if (setsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keep_alive,
                sizeof(keep_alive)) == -1) {
                perror("setsockopt.");
		return 0;
	}

        if (setsockopt(sock_fd, SOL_TCP, TCP_KEEPIDLE, (void *)&keep_idle,
                sizeof(keep_idle)) == -1) {
                perror("setsockopt.");
		return 0;
	}

        if (setsockopt(sock_fd, SOL_TCP, TCP_KEEPINTVL, (void *)&keep_interval,
                sizeof(keep_interval)) == -1) {
                perror("setsockopt.");
		return 0;
	}

        if (setsockopt(sock_fd, SOL_TCP, TCP_KEEPCNT, (void *)&keep_count,
                sizeof(keep_count)) == -1) {
                perror("setsockopt.");
		return 0;
	}

	return 1;
}
