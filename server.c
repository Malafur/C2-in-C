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
int listen(int socket_descriptor, int back_log);
int accept(int socket_descriptor, struct sockaddr *restrict address, socklen_t *restrict length_of_address);

int main(){
	//int sockopt = setsockopt(sockfd, )
	printf("It works!\n");
	return 0;
}