#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <net/if.h>
#define _GNU_SOURCE


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

// Use getservbyport_r() on the server end to get the description for each port.
int ports(){
	int opt = 1;
	int port, count;
	int *ports, *temp;
	struct sockaddr_in sock_addr;
	socklen_t addr_size = sizeof(sock_addr);
	
	// Dynamic array for open ports
	ports = malloc(sizeof(*ports));
    if (ports == NULL) {
        perror("malloc failed");
        return 0;
    }
	
	// Set to IPv4 and localhost ip
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
		setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		
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

// Make struct to store max length of an IP addr
struct ip {
	char if_name[IFNAMSIZ];
	char addr[NI_MAXHOST];
	char netmask[NI_MAXHOST];
};

struct ip get_ipmask(){
	struct ifaddrs *ifaddr;
	int family, h, nm;
	char host[NI_MAXHOST], netmask[NI_MAXHOST];
	struct ip v4, v6;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		
		family = ifa->ifa_addr->sa_family;
		
		// Only includes ipv4 and ipv6 addresses
		if (ifa->ifa_addr == NULL || family != AF_INET && family != AF_INET6 || strcmp(ifa->ifa_name, "lo") == 0)
			continue;
		
		// Retrieves the address
		h = getnameinfo(ifa->ifa_addr,
			(family == AF_INET) ? sizeof(struct sockaddr_in):
								  sizeof(struct sockaddr_in6),
			host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		
		if (h != 0) {
			printf("getnameinfo() failed: %s\n", gai_strerror(h));
			exit(EXIT_FAILURE);
		}
		
		// Retrieves the network mask
		nm = getnameinfo(ifa->ifa_netmask,
			(family == AF_INET) ? sizeof(struct sockaddr_in) :
								  sizeof(struct sockaddr_in6),
					netmask, NI_MAXHOST,
				    NULL, 0, NI_NUMERICHOST);
				   
		if (nm != 0) {
			printf("getnameinfo() failed: %s\n", gai_strerror(nm));
				exit(EXIT_FAILURE);
			}
		
		if (family == AF_INET){
			strcpy(v4.if_name, ifa->ifa_name);
			strcpy(v4.addr, host);
			strcpy(v4.netmask, netmask);
			//printf("IPv4 IF Name: %s\n", v4.if_name);
			//printf("IPv4 Addr: %s\n", v4.addr);
			//printf("IPv4 Netmask: %s\n", v4.netmask);
		}
		
		else if (family == AF_INET6){
			strcpy(v6.if_name, ifa->ifa_name);
			strcpy(v6.addr, host);
			strcpy(v6.netmask, netmask);
			//printf("\nIPv6 IF Name: %s\n", v6.if_name);
			//printf("IPv6 Addr: %s\n", v6.addr);
			//printf("IPv6 Netmask: %s\n", v6.netmask);
		}
		
	}

	freeifaddrs(ifaddr);
	//exit(EXIT_SUCCESS);
	// Change this to include v6 in the future as well
	return v4;
}


int ip_scanner(){
	int opt, total_hosts; opt = total_hosts = 1;
	struct sockaddr_in sock_addr;
	socklen_t addr_size = sizeof(sock_addr);
	
	struct ip v4 = get_ipmask();
	printf("%s\n", v4.netmask);
	unsigned char buff[3];
	
	// Grab the IP addr range
	int s = inet_pton(AF_INET, v4.netmask, buff);

    if (s == 1) {
        printf("Binary: ");
        for (int i = 0; i < 4; i++) {
			if (buff[i] == 255)
				continue;
			printf("%u ", buff[i]);
			int calc = 255 - buff[i];
			//printf("Calc: %d\n", calc);
			total_hosts *= calc;
		}
		printf("\nRange: %d\n", total_hosts);
    }
	
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1){
		perror("Failed to create socket");
		return 0;
	}

	// Set address and port
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(1337);
	sock_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	// Reuse address
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	
	return 0;
}


int main(){
	ip_scanner();
}