#pragma once

#include <string>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

class mySSHClass
{
private:
    char *get_types_name(int type)
    {
        switch (type)
        {
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

    ssh_bind sshbind;
    ssh_session session;
    int auth = 0;
    ssh_message message;

    int port;
    char *address;
    socket_t fd;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char buffer[1024];
    int nbytes;
    int session_fd;
    int rc;
    ssh_channel channel;

public:
    mySSHClass(/* args */);
    ~mySSHClass();

    static int Forwarding(const char *address, int port);
    void CreateSession(int server_port, char *server_address, char *rsa_key, char *dsa_key);
    void DoAuthentication();
    void DoRemotePortForwarding();
};