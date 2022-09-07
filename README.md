# CmakeTemplate
This is a C++ project based on Cmakelits and google test


## Compile and Run

Run following instructions to build the project
+ `git submodule update` to fetch project dependencies (GoogleTest)
+  `mkdir build && cd build` to create a new directory
+ `cmake ..` to generate build configuration files
+ `make all` to build the project and tests
+ `./bbserver` to run client server


## Connect to the server
Run following instructions to connect to the server
+ `ssh-keygen -t rsa`
+ `cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys`
+ `ssh kourosh@localhost -p 1234 -N -R 8080:localhost:4200`


## Project Status
- [x] Create ssh session
- [x] Authenticate ssh session using public key
- [ ] Create a tunnel
    - [x] Read from remote host
    - [ ] Write to the destination host (unable to write to the destination host)
