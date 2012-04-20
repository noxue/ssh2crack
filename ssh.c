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
#include "ssh.h"

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
