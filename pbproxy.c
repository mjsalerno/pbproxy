#include "pbproxy.h"
#include <netinet/if_ether.h>

int main(int argc, char * argv[]) {

    int index, c;
    char *lval = NULL;
    char *kval = NULL;
    char *host_val = NULL;
    char *port_val = NULL;
    FILE *key_file = NULL;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    char *err_at = NULL;
    int srv_sock = -1;
    int cli_sock = -1;
    char buff[BUFF_SIZE];

    opterr = 0;
    while ((c = getopt (argc, argv, "l:k:h")) != -1) {
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
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                print_help(stderr);

                return 1;
            default:
                abort ();
        }
    }

    if((argc - optind) != 2 &&
            (argc - optind) != 0) {
        fprintf(stderr, "Invalid destination\n");
        exit(EXIT_FAILURE);
    }


    for (index = optind; index < argc; index++) {
        if(index == optind) {
            host_val = argv[index];
        } else {
            port_val = argv[index];
        }
    }

    printf ("l = %s, k = %s, h = %s, p = %s\n", lval, kval, host_val, port_val);

    if(lval == NULL) {
        //client mode
    } else {
        //in server mode

        if ((srv_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
            perror("socket() failed");
            return EXIT_FAILURE;
        }

        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family      = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port        = htons(strtoul(lval, &err_at, 10));

        if(*err_at != '\0') {
            fprintf(stderr, "Invalid char in port: %c\n", *err_at);
            return EXIT_FAILURE;
        }

        if(bind(srv_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
            perror("bind() failed");
            return EXIT_FAILURE;
        }

        if(listen(srv_sock, 3) < 0) {
            perror("listen() failed");
            return EXIT_FAILURE;
        }

        for (;;) {
            unsigned int cli_len = sizeof(cli_addr);
            struct sockaddr_in service_addr;
            int service_sock = -1;


            //wait for client
            if ((cli_sock = accept(srv_sock, (struct sockaddr *) &cli_addr, &cli_len)) < 0) {
                perror("accept() failed");
                return EXIT_FAILURE;
            }

            //connect to other service
            if((service_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
                perror("socket() failed");
                return EXIT_FAILURE;
            }

            memset(&service_addr, 0, sizeof(service_addr));
            service_addr.sin_family      = AF_INET;
            service_addr.sin_addr.s_addr = inet_addr(host_val);
            service_addr.sin_port        = htons(echoServPort);

            //do select and connect to ssh

            printf("Handling client %s\n", inet_ntoa(cli_addr.sin_addr));

            if(send(cli_sock, "HELLO", 6, 0) < 0) {
                perror("send() failed");
                return EXIT_FAILURE;
            }
            close(cli_sock);
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

