#ifndef SSH_H
#define SSH_H

#define SSH_TIMEOUT		5
#define SSH_PORT		22

int interactive_auth(ssh_session session, char *passwd);
int password_auth(ssh_session session, char *passwd);
int ssh_auth_methods(ssh_session session, char *passwd);
int ssh2_connect(char *ip, unsigned int port, unsigned int timeout,
                char *user, char *passwd);

#endif
