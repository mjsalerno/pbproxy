#ifndef PBPROXY_H
#define PBPROXY_H

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/tcp.h>

#include "encryption.h"

#define BUFF_SIZE 1024

void print_help(FILE *fd);

#endif
