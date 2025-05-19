#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#define PORT 1337

int socket (int domain, int type, int protocol);
int setsockopt(int sockfd, int level, int option_name, const void *value_of_option, socklen_t option_length);

int bind(int sockfd, const struct sockaddr *my_addr, socklen_t addrlen);
int connect(int socket_descriptor, const struct sockaddr *address, socklen_t length_of_address);


int main(){
	//int sockopt = setsockopt(sockfd, )

	printf("It works!\n");
	return 0;
}