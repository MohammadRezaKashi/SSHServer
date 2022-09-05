#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>


#include <cstdio>
#include <cstdlib>
#include <string>

#include <errno.h>



int forwarding(const char *address, int port)
{    
    int ssh_port = 22;
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

    rc = ssh_channel_open_forward(channel, "localhost", 8080, "localhost", 2000);
    if(rc != SSH_OK) {
        fprintf(stderr, "Error: %s\n", ssh_get_error(my_ssh_session));
        ssh_channel_free(channel);
        exit(1);
    }

    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    if (nbytes < 0)
        return SSH_ERROR;

    nwritten = ssh_channel_write(channel, buffer, nbytes);
    if (nwritten != nbytes)
        return SSH_ERROR;
    
    return SSH_OK;
}


char *get_types_name(int type)
{
    switch(type) {
        case SSH_REQUEST_AUTH:
            return "SSH_REQUEST_AUTH";
        case SSH_REQUEST_CHANNEL_OPEN:
            return "SSH_REQUEST_CHANNEL_OPEN";
        case SSH_REQUEST_CHANNEL:
            return "SSH_REQUEST_CHANNEL";
        case SSH_REQUEST_SERVICE:
            return "SSH_REQUEST_SERVICE";
        case SSH_REQUEST_GLOBAL:
            return "SSH_REQUEST_GLOBAL";
        default:
            return "UNKNOWN";
    }
}

int main(int argc, char **argv)
{
    int server_port = 1234;
    char *server_address = "localhost";
    char *host_key, *rsa_key, *dsa_key;

    ssh_bind sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, server_address);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &server_port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/home/sophie/.ssh/id_rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, "/home/sophie/.ssh/id_dsa");

    if(ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Error listening to socket: %s\n", ssh_get_error(sshbind));
        exit(1);
    }

    ssh_session session = ssh_new();
    if(ssh_bind_accept(sshbind, session) == SSH_ERROR) {
        fprintf(stderr, "Error accepting a connection: %s\n", ssh_get_error(sshbind));
        exit(1);
    }

    if(ssh_handle_key_exchange(session)) {
        fprintf(stderr, "Error exchanging keys: %s\n", ssh_get_error(session));
        exit(1);
    }


    int auth = 0;
    ssh_message message;
    do {
        message = ssh_message_get(session);
        printf("Message type: %s(%d)\n", get_types_name(ssh_message_type(message)), ssh_message_type(message));
        if(message) {
            switch(ssh_message_type(message)) {
                case SSH_REQUEST_AUTH:
                    switch(ssh_message_subtype(message)) {
                        case SSH_AUTH_METHOD_PUBLICKEY:
                            printf("Public key authentication\n");

                            if(ssh_message_auth_publickey_state(message) == SSH_PUBLICKEY_STATE_NONE) {
                                printf("Public key state: SSH_PUBLICKEY_STATE_NONE\n");
                                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                                auth = 1;
                                ssh_message_auth_reply_success(message, 0);
                            } else if(ssh_message_auth_publickey_state(message) == SSH_PUBLICKEY_STATE_VALID) {
                                printf("Public key state: SSH_PUBLICKEY_STATE_VALID\n");
                                auth = 1;
                                ssh_message_auth_reply_success(message, 0);
                            } else {
                                printf("Public key state: SSH_PUBLICKEY_STATE_INVALID\n");
                                ssh_message_reply_default(message);
                            }
                            break;

                        case SSH_AUTH_METHOD_PASSWORD:
                            printf("Password authentication\n");
                            if(strcmp(ssh_message_auth_user(message), "sophie") == 0 &&
                               strcmp(ssh_message_auth_password(message), "allesISTperfekt") == 0) {
                                auth = 1;
                                ssh_message_auth_reply_success(message, 0);
                            } else {
                                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
                                ssh_message_reply_default(message);
                            }
                            break;

                        case SSH_AUTH_METHOD_NONE:
                            printf("User %s tried to connect with no authentication!\n", ssh_message_auth_user(message));
                            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                            ssh_message_reply_default(message);
                            break;
                        
                        default:
                            ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                            ssh_message_reply_default(message);
                    }
                    break;

            
                default:
                    ssh_message_reply_default(message);
            }
            // ssh_message_free(message);
        }
    if(auth) {
        break;
    }
    } while(message != NULL || ssh_get_error_code(session) == SSH_AGAIN);
    

    int port;
    char *address;
    socket_t fd;
    struct addrinfo hints;
    memset(&hints,0,sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol=0;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    struct addrinfo *res = NULL;

    char buffer[1024];
    int nbytes;
    int session_fd;
    int rc;
    ssh_channel channel;
    do {
        message = ssh_message_get(session);
        printf("Message type: %s(%d)\n", get_types_name(ssh_message_type(message)), ssh_message_type(message));
        if(message) {
            switch(ssh_message_type(message)) {
                case SSH_REQUEST_GLOBAL:
                switch(ssh_message_subtype(message)) {
                    case SSH_GLOBAL_REQUEST_TCPIP_FORWARD:
                        printf("User %s wants to forward a port\n", ssh_message_auth_user(message));
                        port = ssh_message_global_request_port(message);
                        address = (char *)ssh_message_global_request_address(message);
                        printf("port: %d, address: %s\n", port, address);
                        ssh_message_global_request_reply_success(message, port);

                        forwarding(address, port);


                        break;
                    default:
                        ssh_message_reply_default(message);
                }
            }
        }
    } while(message != NULL || ssh_get_error_code(session) == SSH_AGAIN);


    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);
}