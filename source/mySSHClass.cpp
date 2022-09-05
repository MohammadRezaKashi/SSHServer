#include "../header/mySSHClass.h"
mySSHClass::mySSHClass(/* args */)
{
}

mySSHClass::~mySSHClass()
{
    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);
}

void mySSHClass::DoRemotePortForwarding()
{
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

    do
    {
        message = ssh_message_get(session);
        printf("Message type: %s(%d)\n", get_types_name(ssh_message_type(message)), ssh_message_type(message));
        if (message)
        {
            switch (ssh_message_type(message))
            {
            case SSH_REQUEST_GLOBAL:
                switch (ssh_message_subtype(message))
                {
                case SSH_GLOBAL_REQUEST_TCPIP_FORWARD:
                    printf("User %s wants to forward a port\n", ssh_message_auth_user(message));
                    port = ssh_message_global_request_port(message);
                    address = (char *)ssh_message_global_request_address(message);
                    printf("port: %d, address: %s\n", port, address);
                    ssh_message_global_request_reply_success(message, port);

                    mySSHClass::Forwarding(address, port);

                    break;
                default:
                    ssh_message_reply_default(message);
                }
            }
        }
    } while (message != NULL || ssh_get_error_code(session) == SSH_AGAIN);
}

void mySSHClass::DoAuthentication()
{
    do
    {
        message = ssh_message_get(session);
        printf("Message type: %s(%d)\n", get_types_name(ssh_message_type(message)), ssh_message_type(message));
        if (message)
        {
            switch (ssh_message_type(message))
            {
            case SSH_REQUEST_AUTH:
                switch (ssh_message_subtype(message))
                {
                case SSH_AUTH_METHOD_PUBLICKEY:
                    printf("Public key authentication\n");

                    if (ssh_message_auth_publickey_state(message) == SSH_PUBLICKEY_STATE_NONE)
                    {
                        printf("Public key state: SSH_PUBLICKEY_STATE_NONE\n");
                        ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
                        auth = 1;
                        ssh_message_auth_reply_success(message, 0);
                    }
                    else if (ssh_message_auth_publickey_state(message) == SSH_PUBLICKEY_STATE_VALID)
                    {
                        printf("Public key state: SSH_PUBLICKEY_STATE_VALID\n");
                        auth = 1;
                        ssh_message_auth_reply_success(message, 0);
                    }
                    else
                    {
                        printf("Public key state: SSH_PUBLICKEY_STATE_INVALID\n");
                        ssh_message_reply_default(message);
                    }
                    break;

                case SSH_AUTH_METHOD_PASSWORD:
                    printf("Password authentication\n");
                    if (strcmp(ssh_message_auth_user(message), "sophie") == 0 &&
                        strcmp(ssh_message_auth_password(message), "allesISTperfekt") == 0)
                    {
                        auth = 1;
                        ssh_message_auth_reply_success(message, 0);
                    }
                    else
                    {
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
        }
        if (auth)
        {
            break;
        }
    } while (message != NULL || ssh_get_error_code(session) == SSH_AGAIN);
}

void mySSHClass::CreateSession(int server_port, char *server_address, char *rsa_key, char *dsa_key)
{
    ssh_bind sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, server_address);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &server_port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, rsa_key);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, dsa_key);

    if (ssh_bind_listen(sshbind) < 0)
    {
        fprintf(stderr, "Error listening to socket: %s\n", ssh_get_error(sshbind));
        exit(1);
    }

    ssh_session session = ssh_new();
    if (ssh_bind_accept(sshbind, session) == SSH_ERROR)
    {
        fprintf(stderr, "Error accepting a connection: %s\n", ssh_get_error(sshbind));
        exit(1);
    }

    if (ssh_handle_key_exchange(session))
    {
        fprintf(stderr, "Error exchanging keys: %s\n", ssh_get_error(session));
        exit(1);
    }
}

int mySSHClass::Forwarding(const char *address, int port)
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

    rc = ssh_userauth_password(my_ssh_session, "kourosh", "allesISTperfekt");
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }

    rc = ssh_channel_listen_forward(my_ssh_session, "localhost", 8080, 0);
    if (rc != SSH_OK)
    {
        fprintf(stderr, "Error: %s\n", ssh_get_error(my_ssh_session));
        exit(1);
    }

    ssh_channel channel = ssh_channel_accept_forward(my_ssh_session, 60000, 0);
    if (channel == NULL)
    {
        fprintf(stderr, "Error creating channel: %s\n", ssh_get_error(my_ssh_session));
        exit(1);
    }

    rc = ssh_channel_open_forward(channel, "localhost", 8080, "localhost", 2000);
    if (rc != SSH_OK)
    {
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