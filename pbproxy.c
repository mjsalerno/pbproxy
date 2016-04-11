#include "pbproxy.h"
#include <netinet/if_ether.h>

int main(int argc, char *argv[]) {

    int index, c, rtn;
    char *lval = NULL;
    char *kval = NULL;
    char *host_val = NULL;
    char *port_val = NULL;
    FILE *key_fd = NULL;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    char *err_at = NULL;
    int srv_sock = -1;
    int cli_sock = -1;
    char buff[BUFF_SIZE];
    char buff_out[BUFF_SIZE];
    char buff_in[BUFF_SIZE];

    opterr = 0;
    while ((c = getopt(argc, argv, "l:k:h")) != -1) {
        switch (c) {
        case 'h':
            print_help(stdout);
            exit(EXIT_SUCCESS);
            break;
        case 'l':
            lval = optarg;
            break;
        case 'k':
            kval = optarg;
            break;
        case '?':
            if (optopt == 'l' || optopt == 'k')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            print_help(stderr);

            return 1;
        default:
            abort();
        }
    }

    if ((argc - optind) != 2 && (argc - optind) != 0) {
        fprintf(stderr, "Invalid destination\n");
        exit(EXIT_FAILURE);
    }

    for (index = optind; index < argc; index++) {
        if (index == optind) {
            host_val = argv[index];
        } else {
            port_val = argv[index];
        }
    }

    // printf ("l = %s, k = %s, h = %s, p = %s\n", lval, kval, host_val, port_val);
    if (kval == NULL) {
        fprintf(stderr, "Please specify a key file.\n");
        return EXIT_FAILURE;
    }

    key_fd = fopen(kval, "r");
    if (key_fd == NULL) {
        perror("fopen()");
        return EXIT_FAILURE;
    }

    char *key[BUFF_SIZE];
    fread(key, BUFF_SIZE, 1, key_fd);
    if (ferror(key_fd)) {
        fprintf(stderr, "Could not read the key file.\n");
        return EXIT_FAILURE;
    }

    if (lval == NULL) {
        // client mode
        int service_sock = -1;
        struct sockaddr_in service_addr;
        fd_set active_fd_set;

        // connect to other service
        if ((service_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            perror("socket() failed");
            return EXIT_FAILURE;
        }

        memset(&service_addr, 0, sizeof(service_addr));
        service_addr.sin_family = AF_INET;
        service_addr.sin_addr.s_addr = inet_addr(host_val);
        service_addr.sin_port = htons(strtoul(port_val, &err_at, 10));

        if (*err_at != '\0') {
            fprintf(stderr, "Invalid char in port: %c\n", *err_at);
            return EXIT_FAILURE;
        }

        if (connect(service_sock, (struct sockaddr *)&service_addr, sizeof(service_addr)) < 0) {
            perror("connect() failed");
            return EXIT_FAILURE;
        }

        // get IV
        memset(buff, 0, BUFF_SIZE);
        rtn = read(service_sock, buff, BUFF_SIZE);
        if (rtn != 8) {
            fprintf(stderr, "Was not an IV: %d, %s\n", rtn, buff);
            return EXIT_FAILURE;
        }
        init_in((unsigned char *)key, (unsigned char *)buff);
        init_out((unsigned char *)key);

        // now send my IV
        int flag = 1;
        setsockopt(cli_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
        send_iv(service_sock);
        flag = 0;
        setsockopt(cli_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

        while (1) {
            memset(buff, 0, BUFF_SIZE);
            memset(buff_in, 0, BUFF_SIZE);
            memset(buff_out, 0, BUFF_SIZE);

            FD_ZERO(&active_fd_set);
            FD_SET(service_sock, &active_fd_set);
            FD_SET(STDIN_FILENO, &active_fd_set);

            if (select(FD_SETSIZE, &active_fd_set, NULL, NULL, NULL) < 0) {
                perror("select()");
                return EXIT_FAILURE;
            }

            if (FD_ISSET(service_sock, &active_fd_set)) {
                // printf("the service socket was set\n");
                // ssize_t read(int fd, void *buf, size_t count);
                rtn = read(service_sock, buff_in, BUFF_SIZE);
                if (rtn == 0) {
                    close(service_sock);
                    close(cli_sock);
                    break;
                } else if (rtn < 0) {
                    perror("read(service)");
                    return EXIT_FAILURE;
                } else {
                    fdecrypt(buff_out, buff_in, rtn);
                    if (write(STDOUT_FILENO, buff_out, rtn) < 0) {
                        perror("send(stdout) failed");
                        return EXIT_FAILURE;
                    }
                }
            }

            if (FD_ISSET(STDIN_FILENO, &active_fd_set)) {
                memset(buff_in, 0, BUFF_SIZE);
                memset(buff_out, 0, BUFF_SIZE);

                rtn = read(STDIN_FILENO, buff_in, BUFF_SIZE);
                if (rtn == 0) {
                    close(service_sock);
                    close(cli_sock);
                    break;
                } else if (rtn < 0) {
                    perror("read(client)");
                    return EXIT_FAILURE;
                } else {
                    fencrypt(buff_out, buff_in, rtn);
                    if (send(service_sock, buff_out, rtn, 0) < 0) {
                        perror("send(service) failed");
                        return EXIT_FAILURE;
                    }
                }
            }
        }

    } else {
        // in server mode

        // get FD to listen with
        if ((srv_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            perror("socket() failed");
            return EXIT_FAILURE;
        }

        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(strtoul(lval, &err_at, 10));

        if (*err_at != '\0') {
            fprintf(stderr, "Invalid char in port: %c\n", *err_at);
            return EXIT_FAILURE;
        }

        if (bind(srv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("bind() failed");
            return EXIT_FAILURE;
        }

        if (listen(srv_sock, 3) < 0) {
            perror("listen() failed");
            return EXIT_FAILURE;
        }

        for (;;) {
            unsigned int cli_len = sizeof(cli_addr);
            struct sockaddr_in service_addr;
            int service_sock = -1;

            fd_set active_fd_set;

            // wait for client
            if ((cli_sock = accept(srv_sock, (struct sockaddr *)&cli_addr, &cli_len)) < 0) {
                perror("accept() failed");
                return EXIT_FAILURE;
            }

            init_out((unsigned char *)key);
            printf("sending the IV\n");
            // send IV
            int flag = 1;
            setsockopt(cli_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
            send_iv(cli_sock);
            flag = 0;
            setsockopt(cli_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

            // now get client IV
            memset(buff, 0, BUFF_SIZE);
            rtn = read(cli_sock, buff, BUFF_SIZE);
            if (rtn != 8) {
                fprintf(stderr, "Was not an IV: %d, %s\n", rtn, buff);
                return EXIT_FAILURE;
            }
            init_in((unsigned char *)key, (unsigned char *)buff);

            // connect to other service
            if ((service_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
                perror("socket() failed");
                return EXIT_FAILURE;
            }

            memset(&service_addr, 0, sizeof(service_addr));
            service_addr.sin_family = AF_INET;
            service_addr.sin_addr.s_addr = inet_addr(host_val);
            service_addr.sin_port = htons(strtoul(port_val, &err_at, 10));

            if (*err_at != '\0') {
                fprintf(stderr, "Invalid char in port: %c\n", *err_at);
                return EXIT_FAILURE;
            }

            if (connect(service_sock, (struct sockaddr *)&service_addr, sizeof(service_addr)) < 0) {
                perror("connect() failed");
                return EXIT_FAILURE;
            }

            // do select and connect to ssh
            while (1) {
                memset(buff, 0, BUFF_SIZE);
                memset(buff_in, 0, BUFF_SIZE);
                memset(buff_out, 0, BUFF_SIZE);

                FD_ZERO(&active_fd_set);
                FD_SET(service_sock, &active_fd_set);
                FD_SET(cli_sock, &active_fd_set);

                if (select(FD_SETSIZE, &active_fd_set, NULL, NULL, NULL) < 0) {
                    perror("select()");
                    return EXIT_FAILURE;
                }

                if (FD_ISSET(service_sock, &active_fd_set)) {
                    printf("the service socket was set\n");
                    // ssize_t read(int fd, void *buf, size_t count);
                    rtn = read(service_sock, buff_in, BUFF_SIZE);
                    if (rtn == 0) {
                        close(service_sock);
                        close(cli_sock);
                        break;
                    } else if (rtn < 0) {
                        perror("read(service)");
                        return EXIT_FAILURE;
                    } else {
                        fencrypt(buff_out, buff_in, rtn);
                        if (send(cli_sock, buff_out, rtn, 0) < 0) {
                            perror("send() failed");
                            return EXIT_FAILURE;
                        }
                    }
                }

                if (FD_ISSET(cli_sock, &active_fd_set)) {
                    printf("the client socket was set\n");
                    memset(buff_in, 0, BUFF_SIZE);
                    memset(buff_out, 0, BUFF_SIZE);

                    rtn = read(cli_sock, buff_in, BUFF_SIZE);
                    if (rtn == 0) {
                        close(service_sock);
                        close(cli_sock);
                        break;
                    } else if (rtn < 0) {
                        perror("read(client)");
                        return EXIT_FAILURE;
                    } else {
                        fdecrypt(buff_out, buff_in, rtn);
                        if (send(service_sock, buff_out, rtn, 0) < 0) {
                            perror("send() failed");
                            return EXIT_FAILURE;
                        }
                    }
                }
            }
        }
    }

    return EXIT_SUCCESS;
}

void print_help(FILE *fd) {
    fprintf(fd, "pbproxy [-l port] -k keyfile destination port\n\n");
    fprintf(fd, "  -l  Reverse-proxy mode: listen for inbound connections on <port> and relay\n");
    fprintf(fd, "      them to <destination> <port>\n\n");
    fprintf(fd, "  -k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)\n");
}
