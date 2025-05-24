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
int port_scanner(){
	int opt = 1;
	int port, count;
	int *ports;
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
			ports = realloc(ports, (count + 1)*sizeof(*ports));
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
	char net_addr[NI_MAXHOST];
	char bro_addr[NI_MAXHOST];
};

struct ip v4, v6;

struct ip get_ipmask(){
	struct ifaddrs *ifaddr;
	int family, h, nm;
	char host[NI_MAXHOST], netmask[NI_MAXHOST];

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
			//strcpy(v4.net_addr, "");
			//strcpy(v4.bro_addr, "");
		}
		
		else if (family == AF_INET6){
			strcpy(v6.if_name, ifa->ifa_name);
			strcpy(v6.addr, host);
			strcpy(v6.netmask, netmask);
			//strcpy(v6.net_addr, "");
			//strcpy(v6.bro_addr, "");
		}
		
	}

	freeifaddrs(ifaddr);
	//exit(EXIT_SUCCESS);
	// Change this to include v6 in the future as well
	return v4;
}

int ip_range_calc(){
	get_ipmask();
	
	printf("%s", v4.net_addr);

	uint8_t sub_buff[4];
	uint8_t ip_buff[4];
	
	// Add null terminator to the end
	v4.netmask[NI_MAXHOST - 1] = v4.addr[NI_MAXHOST - 1] = '\0';
	
	printf("%s\n", v4.netmask);
	printf("%s\n", v4.addr);
	
	// Grab the IP addr range
	int sub_res = inet_pton(AF_INET, v4.netmask, sub_buff);
	int ip_res = inet_pton(AF_INET, v4.addr, ip_buff);

    if (sub_res == 1 && ip_res == 1) {
		for (int i = 0; i < 4; i++) {
			uint8_t and_sub = sub_buff[i] & ip_buff[i];
			uint8_t and_not_sub = ip_buff[i] | ~sub_buff[i];
			
			ssize_t len;
			
			if (i == 3){
				len = strlen(v4.net_addr);
				snprintf(v4.net_addr + len, sizeof(v4.net_addr) - len, "%d", and_sub);
				len = strlen(v4.bro_addr);
				snprintf(v4.bro_addr + len, sizeof(v4.bro_addr) - len, "%d", and_not_sub);
			}
			else{
				len = strlen(v4.net_addr);
				snprintf(v4.net_addr + len, sizeof(v4.net_addr) - len, "%d.", and_sub);
				len = strlen(v4.bro_addr);
				snprintf(v4.bro_addr + len, sizeof(v4.net_addr) - len, "%d.", and_not_sub);
			}
		}
		printf("\n");
		printf("net_addr: %s\n", v4.net_addr);
		printf("bro_addr: %s\n", v4.bro_addr);
	}
	return 0;
}


int ip_scanner(){
	int opt, total_hosts, calc; opt = 1;
	struct sockaddr_in sock_addr;
	socklen_t addr_size = sizeof(sock_addr);
	
	printf("%s\n", v4.net_addr);
	
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
	ip_range_calc();
	ip_scanner();
}