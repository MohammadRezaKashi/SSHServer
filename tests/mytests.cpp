#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>


#include <cstdio>
#include <cstdlib>
#include <string>

#include <errno.h>

int main()
{
    int ssh_port = 1234;
    int nbytes, nwritten;
    char buffer[1024];
    ssh_session my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &ssh_port);

    int rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error connecting to localhost: %s\n",
                ssh_get_error(my_ssh_session));
        exit(-1);
    }

    rc = ssh_userauth_password(my_ssh_session, "sophie", "allesISTperfekt");
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }


    rc = ssh_channel_listen_forward(my_ssh_session, "localhost", 8080, 0);
    if(rc != SSH_OK) {
        fprintf(stderr, "Error: %s\n", ssh_get_error(my_ssh_session));
        exit(1);
    }

    ssh_channel channel = ssh_channel_accept_forward(my_ssh_session, 60000, 0);
    if (channel == NULL) {
        fprintf(stderr, "Error creating channel: %s\n", ssh_get_error(my_ssh_session));
        exit(1);
    }

    rc = channel_open_forward(channel, "localhost", 8080, "localhost", 2000);
    if(rc != SSH_OK) {
        fprintf(stderr, "Error: %s\n", ssh_get_error(my_ssh_session));
        ssh_channel_free(channel);
        exit(1);
    }
    
    return 0;
}