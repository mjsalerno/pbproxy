#include "pbproxy.h"
#include <netinet/if_ether.h>

int main(int argc, char * argv[]) {

    int index, c;
    char *lval = NULL;
    char *kval = NULL;
    char *dst_val = NULL;
    FILE *key_file = NULL;

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

    printf ("l = %s, k = %s\n", lval, kval);

    for (index = optind; index < argc; index++) {
        dst_val = argv[index];
        if(index > optind) {
            fprintf(stderr, "Invalid destination\n");
            exit(EXIT_FAILURE);
        }
    }

    return EXIT_SUCCESS;
}

void print_help(FILE *fd) {
    fprintf(fd, "pbproxy [-l port] -k keyfile destination port\n\n");
    fprintf(fd, "  -l  Reverse-proxy mode: listen for inbound connections on <port> and relay\n");
    fprintf(fd, "      them to <destination>:<port>\n\n");
    fprintf(fd, "  -k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)\n");
}

