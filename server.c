#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define PORT 1337


int main(){
	int opt = 1;
	char buffer[1024];
	int backlog = 5;
	int sockopt;
	struct sockaddr_in sock_addr;
	socklen_t addr_size = sizeof(sock_addr);
	
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (sockfd == -1){
		perror("Failed to create socket");
		return 0;
	}

	// Set address and port
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(PORT);
	sock_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	
	// Reuse address and port
	sockopt = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	sockopt = setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
	// Buffer size for send and receive
	sockopt = setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer));
	sockopt = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer));
	
	bind(sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
	listen(sockfd, backlog);
	
	int conn = accept(sockfd, (struct sockaddr *)&sock_addr, &addr_size);
	
	strcpy(buffer, "Hello from server!");
	write(conn, buffer, strlen(buffer));
	recv(conn, buffer, sizeof(buffer), 0);
	printf("Server received: %s\n", buffer);
	
	return 0;
}