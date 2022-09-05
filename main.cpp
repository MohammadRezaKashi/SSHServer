#include <cstdio>
#include <cstdlib>
#include <string>

#include <errno.h>

#include "./header/mySSHClass.h"

int main(int argc, char **argv)
{
    int server_port = 1234;
    char *server_address = "localhost";
    char *rsa_key = "/home/kourosh/.ssh/id_rsa";
    char *dsa_key = "/home/kourosh/.ssh/id_dsa";

    mySSHClass m_mySSHClass;

    m_mySSHClass.CreateSession(server_port, server_address, rsa_key, dsa_key);
    m_mySSHClass.DoAuthentication();
    m_mySSHClass.DoRemotePortForwarding();
}