#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

int sys_info(){
	struct utsname uts;
	
	// uname()
	if (uname(&uts) < 0){
		perror("uname error");
	}
	else{
		printf("Sysname: %s\n", uts.sysname);
		printf("Nodename: %s\n", uts.nodename);
		printf("Release:  %s\n", uts.release);
		printf("Version:  %s\n", uts.version);
		printf("Machine:  %s\n", uts.machine);
	}
	
	return 0;
}

int ports(){
	int opt = 1;
	int port;
	int *ports, *temp;
	int count;
	int sockopt;
	struct sockaddr_in sock_addr;
	socklen_t addr_size = sizeof(sock_addr);
	
	
	ports = malloc(sizeof(*ports));
    if (ports == NULL) {
        perror("malloc failed");
        return 0;
    }
	
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	for (port = 0; port <= 65535; port++){
		
		int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd == -1){
			perror("Failed to create socket");
			return 0;
		}
		
		printf("PORT: %d\n", port);
		
		sock_addr.sin_port = htons(port);
		
		sockopt = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		
		int conn = connect(sockfd, (struct sockaddr *)&sock_addr, addr_size);
		if (conn == -1){
			perror("Connection error");
			//sleep(0.1);
			close(sockfd);
			continue;
		}
		else if (conn != -1){
			temp = realloc(ports, (count + 1)*sizeof(*ports));
			ports = temp;
			ports[count++] = port;
			printf("Port open: %i\n", port);
			close(sockfd);
		}
	}
	
	printf("Found open ports: ");
	for(int i = 0; i < count; i++){
		if (i == count - 1){
			printf("%d\n", ports[i]);
		}
		else{
			printf("%d,", ports[i]);
		}
	}
	
	free(ports);
	return 0;

}

int main(){
	ports();
}


