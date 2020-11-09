/*
 
 gcc -g -w sniffflow_bak.c -I /root/openssl-1.0.1/include/openssl -o sniffflow_bak -lpthread -lssl -lcrypto

*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <signal.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pthread.h>
#include <sys/types.h>
#include <fcntl.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
int httpGetNum;
int httpResNum;
int httpsGetNum;
int httpsResNum;

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

struct tcp_status
{
    unsigned long ipaddr;
    unsigned int port;

    unsigned int socket;
    unsigned int synFlag;
    unsigned int synAckFlag;
    unsigned int ackFlag;

    unsigned int finFlag;
    unsigned int sFinAckFlag;
    unsigned int rFinAckFlag;
    unsigned int sAckForFinFlag;

    unsigned long seq;
    unsigned long ack_num;

    unsigned long cSynSeq;
    unsigned long cSynAck;

    unsigned long cSynAckSeq;
    unsigned long cSynAckAck;

    unsigned long cAckSeq;
    unsigned long cAckAck;

    unsigned long cFinSeq;
    unsigned long cFinAck;

    unsigned long cFinAckSeq;
    unsigned long cFinAckAck;

    unsigned long cFinBackAckSeq;
    unsigned long cFinBackAckAck;
  
//    struct timeval start;
//    struct timeval end;
    double start;
    double end;

    struct tcp_status *next;
};
struct tcp_status tcp_sniff;
typedef uint32_t ipv4_t;
char srcip[16] = "";
char serverIp[16] = "";
int serverPort;
int sniffType;
int sniffCount = 10;
int sniffTime = 60;
int sniffRate = 1000000;
struct timeval start, end;
int connectNum = 0;
int connectFailNum = 0;
char dnsString[1024] = "";

struct tcp_status *g_tcp_status_list[65535];

int hash_key_function(unsigned long key, int port)
{
    return htonl(key + port) % (65535);
}    

struct tcp_status *lookup(unsigned long ipaddr, unsigned int port)
{
    unsigned int hashIndex = hash_key_function(ipaddr, port);
    struct tcp_status *item = g_tcp_status_list[hashIndex];

    for(;item != NULL;item = item->next)
    {
        if(item->ipaddr == ipaddr && item->port == port)
        {
            return item;
        }
    }
    return NULL;
}

int update_syn_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned ack_num, int fd, double start)
{
    unsigned int hashIndex;

    struct tcp_status *item;
    if((item = lookup(ipaddr, port)) == NULL)
    {
        hashIndex = hash_key_function(ipaddr, port);
        item = (struct tcp_status*)malloc(sizeof(struct tcp_status));
        if(item == NULL)
            return 0;
        item->ipaddr = ipaddr;
        item->port = port;
        item->synFlag = 1;
        item->cSynSeq = seq;
        item->cSynAck = ack_num;
        item->socket = fd;
	item->start = start;
        //sendSynPacketNum++;
        item->next = g_tcp_status_list[hashIndex];
        g_tcp_status_list[hashIndex] = item;
    }
    else
    {
        item->ipaddr = ipaddr;
        item->port = port;
        item->synFlag = 1;
        item->cSynSeq = seq;
        item->cSynAck = ack_num;
        item->socket = fd;
	item->start = start;
        //sendSynPacketNum++;
    }
    if(item->ipaddr ==0 && item->port ==0) return 0;
    return 1;
}

int update_synack_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned long ack_num, int syn, int ack, int fd)
{
    struct tcp_status *item;
    unsigned int hashIndex;

    hashIndex = hash_key_function(ipaddr, port);
    item = g_tcp_status_list[hashIndex];

    for(;item != NULL;item = item->next)
    {
	if(item->ipaddr == ipaddr && item->port == port)
	{
	    item->synAckFlag = 1;
	    item->cSynAckSeq = seq;
	    item->cSynAckAck = ack_num;
	    item->socket = fd;
	    //recvSynAckPacketNum++;
	}
    }
}

int update_ack_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned long ack_num, int fd, double end)
{
    struct tcp_status *item;
    unsigned int hashIndex;

    hashIndex = hash_key_function(ipaddr, port);
    item = g_tcp_status_list[hashIndex];

    for(;item != NULL;item = item->next)
    {
	if(item->ipaddr == ipaddr && item->port == port)
	{
   	    item->ackFlag = 1;
	    item->cAckSeq = seq;
	    item->cAckAck = ack_num;
	    item->socket = fd;
	    item->end = end;
	    //threeHandshakeNum++;
	}
    }
}

unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

int socketfd[10];
void tcp_recieve_thread(void * arg)
{
    int num = (void *)arg;
    socketfd[num] = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (socketfd[num] < 0)
    {
        printf( "%s", strerror(errno));
        return;
    }
    int opt = 1;
    int bufsize = 50 * 1024;
    int flag1 = setsockopt( socketfd[num], IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    int flag2 = setsockopt( socketfd[num], SOL_SOCKET, SO_RCVBUF,&bufsize,sizeof(bufsize));

    while(1)
    {
        char rcvbuf[1024] = "";
        struct sockaddr_in client;
        int len =  sizeof(client);
        int irecvsize = recvfrom(socketfd[num], rcvbuf, 1024, 0, (struct sockaddr *)&client, &len);
        if(0 > irecvsize)
        {
            close(socketfd);
            exit(1);
        }
        else
        {
        //    printf("recieve syn+ack  packet ..............\n");
        }
        int i, findIp = 0;
        char sourceIp[16] = "";
        char destIp[16] = "";
        struct sockaddr_in source, dest;
        struct iphdr *ip1 = (struct iphdr *)(rcvbuf);
        int iphdrlen1 = ip1->ihl*4;
        struct tcphdr *tcpkt=(struct tcphdr*)(rcvbuf + iphdrlen1);

        struct sockaddr_in abc, def;
        memset(&abc, 0, sizeof(abc));
        abc.sin_addr.s_addr = ip1->saddr;

        memset(&def, 0, sizeof(def));
        def.sin_addr.s_addr = ip1->daddr;
        char sour[16] = "";
        char dst[16] = "";
        strcpy(sour, inet_ntoa(abc.sin_addr));
        strcpy(dst, inet_ntoa(def.sin_addr));

        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));
        source.sin_addr.s_addr = ip1->saddr;
        dest.sin_addr.s_addr = ip1->daddr;
        strcpy(sourceIp, inet_ntoa(source.sin_addr));
        strcpy(destIp, inet_ntoa(dest.sin_addr));

        if(!strncmp(srcip, dst, strlen(srcip)))
        {
            findIp = 1;
        }
        if(findIp == 1 && ntohs(tcpkt->source) == serverPort && !strstr(sourceIp, "254"))//&& tcp_sniff.synAckFlag != 1)
        {

            struct iphdr *sendip;
            struct tcphdr *sendtcp;
            struct sockaddr_in addr;
            char cSendbuff[sizeof(struct iphdr) + sizeof(struct tcphdr)];

            memset(cSendbuff, 0x0, sizeof(cSendbuff));
            sendip = (struct iphdr *)cSendbuff;
            sendtcp = (struct tcphdr *)(cSendbuff + sizeof(struct iphdr));

            sendip->ihl = 5;
            sendip->version = 4;
            sendip->tos = 0;
            sendip->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
            sendip->id = htonl(54321);
            sendip->frag_off = 0;
            sendip->ttl = 64;
            sendip->protocol = IPPROTO_TCP;
            sendip->check = 0;
            sendip->saddr = ip1->daddr;
            sendip->daddr = ip1->saddr;
            sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

            sendtcp->source = tcpkt->dest;
            sendtcp->dest = tcpkt->source;
            sendtcp->seq = htonl(ntohl(tcpkt->ack_seq));
            sendtcp->ack_seq = htonl(ntohl(tcpkt->seq)+1);
            sendtcp->doff = 5;
            sendtcp->syn = 0;
            sendtcp->rst=0;
            sendtcp->psh=0;
            sendtcp->ack=1;
            sendtcp->urg=0;
            sendtcp->window = htons (5840);
            sendtcp->check = 0;
            sendtcp->urg_ptr = 0;

            char *pseudogram;
            struct pseudo_header psh;
            psh.source_address = inet_addr(destIp);
            psh.dest_address = inet_addr(sourceIp);
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_length = htons(sizeof(struct tcphdr));

            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
            pseudogram = malloc(psize);
            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
            memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
            sendtcp->check = 0;
            sendtcp->check = csum( (unsigned short*) pseudogram , psize);

            memset( &addr, 0x0, sizeof(struct sockaddr_in));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(serverPort);
            addr.sin_addr.s_addr = inet_addr(serverIp);

            struct sockaddr_in source, dest;
            memset(&source, 0, sizeof(source));
            memset(&dest, 0, sizeof(dest));

            source.sin_addr.s_addr = sendip->saddr;
            dest.sin_addr.s_addr = sendip->daddr;
            char sourceIp[16] = "";
            char destIp[16] = "";
            strcpy(sourceIp, inet_ntoa(source.sin_addr));
            strcpy(destIp, inet_ntoa(dest.sin_addr));

            struct tcp_status *item;
            if((item = lookup(inet_addr(sourceIp), ntohs(sendtcp->source))) != NULL)
            {
            if(tcpkt->syn != 1 && tcpkt->ack != 1)
            {
                connectFailNum++;		    
            }
                if(item->synFlag == 1 && item->synAckFlag != 1)
                {
                    update_synack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), sendtcp->syn, sendtcp->ack, socketfd[num]);
                    int isendsize = -1;
                    isendsize = sendto(socketfd[num], cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                    if(isendsize < 0)
                    {
                        printf("======send tcp ack message failed======\n");
                    }
                    connectNum++;
                    struct timeval start_time, end_time;
                    struct timezone dummy;
                    if (gettimeofday(&end_time, &dummy) != 0)
                        perror("bad gettimeofday");
                    double delta = (end_time.tv_sec + (end_time.tv_usec / 1000000.0));		
                    update_ack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), socketfd[num], delta);
                    double tmp = (item->end)-(item->start);
                    //printf("connect TIMER[%.4f]\n", tmp);
                    if(connectNum == sniffCount)
                    {
                        printf("connect over\n");
                        printf("connect fail num is: %d\n", connectFailNum);
                        pthread_exit(0);
                    }
                }
            }
        }
    }
}

void tcp_sniff_fun(char *serverIp, int serverPort, int sniffCount, int sniffTime)
{
    int i;
    for(i=0;i<sniffCount;i++)
    { 
        int s;
        unsigned int sendSrcPort;
        unsigned long sendSeq;
        unsigned long sendAck; 
        unsigned int seq = 0;
        unsigned int ack = 0;
        s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP); 
        if(s == -1)
        {
            perror("Failed to create socket");
            exit(1);
        }
        
        char datagram[4096] , source_ip[32] , *data , *pseudogram;
        memset (datagram, 0, 4096);

        struct iphdr *iph = (struct iphdr *) datagram; 
        struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
        struct sockaddr_in sin;
        struct pseudo_header psh;
        
        //data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
        //strcpy(data , "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        
        strcpy(source_ip , srcip);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(serverPort);
        sin.sin_addr.s_addr = inet_addr (serverIp);
        
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);//+ strlen(data);
        iph->id = htonl (54321);
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = inet_addr (srcip);
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
        sendSrcPort = random()%65535;	
        tcph->source = htons (sendSrcPort);//1234);
        tcph->dest = htons (serverPort);
        sendSeq = random() % 65535;
        sendAck = 0;
        //seq = random() % 65535;
        tcph->seq = htonl(sendSeq);
        tcph->ack_seq = htonl(0);
        tcph->doff = 5;
        tcph->fin=0;
        tcph->syn=1;
        tcph->rst=0;
        tcph->psh=0;
        tcph->ack=0;
        tcph->urg=0;
        tcph->window = htons (5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        
        psh.source_address = inet_addr(source_ip);
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));// + strlen(data));
        
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr); //+ strlen(data);
        pseudogram = malloc(psize);
        
        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr)); //+ strlen(data));
        
        tcph->check = csum( (unsigned short*) pseudogram , psize);
        
        int one = 1;
        const int *val = &one;

        if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
        {
            perror("Error setting IP_HDRINCL");
            exit(0);
        }
        //gettimeofday(&start, NULL);

        struct tcp_status *item;
        if((item = lookup(inet_addr(srcip), sendSrcPort)) == NULL)
        {
            struct timeval start_time, end_time;
            struct timezone dummy;
            if (gettimeofday(&start_time, &dummy) != 0)
              	perror("bad gettimeofday");
            double delta = /*(end_time.tv_sec + (end_time.tv_usec / 1000000.0));//-*/(start_time.tv_sec + (start_time.tv_usec / 1000000.0));
            update_syn_hash_table(inet_addr(srcip), sendSrcPort, sendSeq, sendAck, s, delta);
            if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            {
                perror("sendto failed");
            }
        }
        usleep(sniffRate);
    }
}


ipv4_t util_local_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof (addr);

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
    #ifdef DEBUG
        printf("[util] Failed to call socket(), errno = %d\n", errno);
    #endif
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);

    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}

void init_tcp_status_hash_list()
{
    int i;
    for(i=0;i<65535;i++)
        g_tcp_status_list[i] = NULL;
}

void check_tcp_connect_status()
{
    int i;
    int totalSuccessNum = 0;
    struct tcp_status *item = NULL;
    double averageTime;
    
    printf("Total connect num: %d, connect fail num: %d, success num %d\n", sniffCount, connectFailNum, sniffCount-connectFailNum);
   
    double maxNum;
    double minNum;
    int flag = 0;
    for(i=0;i<65535;i++)
    {
        item = g_tcp_status_list[i];
        for(;item != NULL;item = item->next)
        {
            double tmp = (item->end)-(item->start);
            if(tmp > 0)
            {
                averageTime += tmp;
                //printf("tmp time is [%.4f]\n", tmp);
            }
            if(tmp > maxNum)
            {
                maxNum = tmp;
            }
            if(flag == 0 && tmp > 0)
            {
                minNum = tmp;
                flag = 1;
            }
            if(minNum > tmp && tmp > 0)
            {
                minNum = tmp;
            }
            if(item->synFlag == 1 && item->synAckFlag == 1 && item->ackFlag == 1)
            {
                totalSuccessNum++;
            }
        }
    }
    printf("max time is [%.4f]\n", maxNum);
    printf("min time is [%.4f]\n", minNum);
    printf("total time is [%.4f]\n", averageTime);
    printf("average time is [%.6f]\n", (double)averageTime/sniffCount);
    printf("total success connect num %d\n", totalSuccessNum);
}

void http_sniff_fun(char *serverIp, int serverPort, int sniffCount, int sniffTime)
{
    int j;
    double maxTime;
    double minTime;
    int flag;
    for(j=0; j < sniffCount; j++)
    {
        char buffer[BUFSIZ];
        enum CONSTEXPR { MAX_REQUEST_LEN = 1024};
        char request[MAX_REQUEST_LEN];
        char request_template[] = "GET / HTTP/1.1\r\nHost: %s\r\n\r\n";
        struct protoent *protoent;
        char *hostname = "10.10.14.12";
        in_addr_t in_addr;
        int request_len;
        int socket_file_descriptor;
        ssize_t nbytes_total, nbytes_last;
        struct hostent *hostent;
        struct sockaddr_in sockaddr_in;
        unsigned short server_port = 80;

        struct timeval start_time, end_time;
        struct timezone dummy;

        if (gettimeofday(&start_time, &dummy) != 0)
            perror("bad gettimeofday");

        request_len = snprintf(request, MAX_REQUEST_LEN, request_template, hostname);
        if (request_len >= MAX_REQUEST_LEN) {
            fprintf(stderr, "request length large: %d\n", request_len);
            exit(EXIT_FAILURE);
        }

        protoent = getprotobyname("tcp");
        if (protoent == NULL) {
            perror("getprotobyname");
            exit(EXIT_FAILURE);
        }
        socket_file_descriptor = socket(AF_INET, SOCK_STREAM, protoent->p_proto);
        if (socket_file_descriptor == -1) {
            perror("socket");
            exit(EXIT_FAILURE);
        }

        sockaddr_in.sin_addr.s_addr = inet_addr("10.10.14.12");
        sockaddr_in.sin_family = AF_INET;
        sockaddr_in.sin_port = htons(server_port);

        if (connect(socket_file_descriptor, (struct sockaddr*)&sockaddr_in, sizeof(sockaddr_in)) == -1) {
            perror("connect");
            exit(EXIT_FAILURE);
        }

        nbytes_total = 0;

        while (nbytes_total < request_len) {
            nbytes_last = write(socket_file_descriptor, request + nbytes_total, request_len - nbytes_total);
            if (nbytes_last == -1) {
                perror("write");
                exit(EXIT_FAILURE);
            }
            nbytes_total += nbytes_last;
        }
        httpGetNum++;

        nbytes_total = 0;

        if ((nbytes_total = read(socket_file_descriptor, buffer, BUFSIZ)) > 0)
        {

            httpResNum++;
            if (gettimeofday(&end_time, &dummy) != 0)
                perror("bad gettimeofday");
            double delta = ((end_time.tv_sec + (end_time.tv_usec / 1000000.0))-(start_time.tv_sec + (start_time.tv_usec / 1000000.0)));

            if(maxTime < delta)
            {
                maxTime = delta;
            }
            if(flag == 0)
            {
                minTime = delta;
                flag = 1;
            }
            if(delta < minTime)
            {
                minTime = delta;
            }

        }

        if (nbytes_total == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        close(socket_file_descriptor);
 
        usleep(sniffRate);
    }
    printf("http get total num: %d, http respond num: %d, http get fail num: %d\n", httpGetNum, httpResNum, httpGetNum-httpResNum);
    printf("http get max time: [%.4f]\n", maxTime);
    printf("http get min time: [%.4f]\n", minTime);
    exit(0);
}

const char* DEST_IP = "61.135.169.121";
const int DEST_PORT = 443;
const char* REQUEST = "GET / HTTP/1.1\nHost: www.baidu.com\r\n\r\n";

void https_sniff_fun(char *serverIp, int serverPort, int sniffCount, int sniffTime)
{
    int j;
    double maxTime;
    double minTime;
    int flag = 0;
    for(j=0; j < sniffCount; j++)
    {
        SSL_load_error_strings();
        SSL_library_init();
        SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method());

        struct timeval start_time, end_time;
        struct timezone dummy;

        if (gettimeofday(&start_time, &dummy) != 0)
          perror("bad gettimeofday");

        int sockfd = socket(PF_INET, SOCK_STREAM, 0);
        if (sockfd == -1)
        {
            perror("Unable to create socket");
            return 1;
        }

        int flags = fcntl(sockfd, F_GETFL, 0);

        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(DEST_PORT);
        dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);
        memset(&(dest_addr.sin_zero), '\0', 8);

        int status = connect(sockfd, (struct sockaddr*) &dest_addr, sizeof(struct sockaddr_in));
        if (status == -1)
        {
            perror("Unable to connect to the server");
            close(sockfd);
            return 1;
        }

        SSL *conn = SSL_new(ssl_ctx);
        SSL_set_fd(conn, sockfd);
        SSL_connect(conn);

        ssize_t sendsize = SSL_write(conn, REQUEST, strlen(REQUEST));
        if (sendsize == -1)
        {
            perror("Unable to send to the server");
            {
                char buf[256];
                u_long err;

                while ((err = ERR_get_error()) != 0)
                {
                    ERR_error_string_n(err, buf, sizeof(buf));
                    printf("*** %s\n", buf);
                }
            }
            SSL_shutdown(conn);
            SSL_free(conn);
            close(sockfd);
            return 1;
        }
        else
        {
            httpsGetNum++;
        }

        int len;
        int count;
        ssize_t recsize;

        const int RESPONSE_SIZE = 512;
        char response[RESPONSE_SIZE];
        recsize = SSL_read(conn, response, RESPONSE_SIZE-1);
        if (recsize == -1)
        {
            perror("Unable to send to the server");
            SSL_shutdown(conn);
            SSL_free(conn);
            close(sockfd);
            return 1;
        }
        response[recsize] = '\0';

        if(recsize > 0)
        {
            if (gettimeofday(&end_time, &dummy) != 0)
                perror("bad gettimeofday");
            httpsResNum++;
            double delta = ((end_time.tv_sec + (end_time.tv_usec / 1000000.0))-(start_time.tv_sec + (start_time.tv_usec / 1000000.0)));

            if(maxTime < delta)
            {
                maxTime = delta;
            }
            if(flag == 0)
            {
                minTime = delta;
                flag = 1;
            }
            if(delta < minTime)
            {
                minTime = delta;
            }
        }
        if (recsize < 0)
        {
            SSL_shutdown(conn);
            SSL_free(conn);
            close(sockfd);
            printf("http respond error");
            return 0;
        }
        SSL_shutdown(conn);
        SSL_free(conn);
        close(sockfd);
        usleep(sniffRate);
    }
    printf("https get total num: %d, https respond num: %d, https get fail num: %d\n", httpsGetNum, httpsResNum, httpsGetNum-httpsResNum);
    printf("https get max time: [%.4f]\n", maxTime);
    printf("https get min time: [%.4f]\n", minTime);
    exit(0);
}

void dns_sniff_fun(char *dnsServerIp, int sniffCount, int sniffTime)
{
    int j;
    printf("dns query time:\n");
    for(j=0; j < sniffCount; j++)
    {
        char dnsQuery[1024] = "";
        sprintf(dnsQuery, "dig @%s %s | grep \"Query time\" | awk '{print $4 \" \" $5}'", dnsServerIp , dnsString);
        system(dnsQuery);
        usleep(sniffRate);
    }
    exit(0);
}

void usage()
{
    printf("usage:\n");
    printf("sniffflow -d 172.168.1.2 -y 80 -t 0 -c 10 -s 5, explan: -d dest ip -t: tcp type\n");
    printf("sniffflow -d 172.168.1.13 -y 80 -t 1 -s 10 -c 20, explan: -d dest ip -t: http type\n");
    printf("sniffflow -d 172.168.1.13 -y 80 -t 2 -s 10 -c 20, explan: -d dest ip -t: https type\n");
    printf("sniffflow -d 172.168.1.13 -t 3 -s 10 -c 20 -q www.163.com, explan: -d: dns server ip -t: dns query -q: query url \n");
}

int main(int argc, char *argv[])
{
    char c;

    struct timeval start_time, end_time;
    struct timezone dummy;

    if (gettimeofday(&start_time, &dummy) != 0)
              perror("bad gettimeofday");

    while ((c = getopt(argc, argv, "d:y:t:c:s:q:")) != EOF)
    {
        switch(c)
        {
        case 'd':
            strcpy(serverIp, optarg);
            printf("_______%s_________\n", serverIp);
            break;
        case 'y':
            serverPort = atoi(optarg);
            printf("_________%d_________\n", serverPort);
            break;
        case 't':
            sniffType = atoi(optarg);
            printf("_________%d_________\n", sniffType);
            break;
        case 'c':
            sniffCount = atoi(optarg);
            printf("_________%d_________\n", sniffCount);	
            break;
        case 's':
            sniffTime = atoi(optarg);
            printf("_________%d_________\n", sniffTime);
            break;
        case 'q':
            strcpy(dnsString, optarg);
            printf("_________%s_________\n", dnsString);
            break;
        case 'h':
            usage();
            break;
        default:
            usage();
            //exit(0);
            break;
        }
    }
    if (gettimeofday(&end_time, &dummy) != 0)
        perror("bad gettimeofday");

    double delta = ((end_time.tv_sec + (end_time.tv_usec / 1000000.0))-(start_time.tv_sec + (start_time.tv_usec / 1000000.0)));
    printf("TIMER[%.4f]\n", delta);

    float tmp1 = (float)sniffTime/sniffCount;
    printf("%.1f\n",tmp1);

    float tmp2 = (float)sniffRate*tmp1;
    sniffRate = (int)tmp2;
    printf("_________%d_________\n", sniffRate);
 

    struct timeval start, end;
    gettimeofday( &start, NULL );
    printf("start : %d.%d\n", start.tv_sec, start.tv_usec);

    struct in_addr sIP;
    ipv4_t LOCAL_ADDR;
    LOCAL_ADDR = util_local_addr();
    sIP.s_addr = LOCAL_ADDR;
    strcpy(srcip, inet_ntoa(sIP));
    printf("tcpattack: src ip is %s\n", srcip);

    //gettimeofday( &end, NULL );
    //printf("end   : %d.%d\n", end.tv_sec, end.tv_usec);

    if(sniffType == 0)
    {
        //tcp_sniff_fun(serverIp, serverPort, sniffCount, sniffTime);
        tcp_sniff.synFlag = 0;
        tcp_sniff.synAckFlag = 0;
        tcp_sniff.ackFlag = 0;

        tcp_sniff.cSynSeq = 0;
        tcp_sniff.cSynAck = 0;

        tcp_sniff.cSynAckSeq = 0;
        tcp_sniff.cSynAckAck = 0;

        tcp_sniff.cAckSeq = 0;
        tcp_sniff.cAckAck = 0;

        init_tcp_status_hash_list();

        pthread_t thrd_tcp_recieve[5];
        int j;
        for(j=0;j<10;j++)
        {
            pthread_create(thrd_tcp_recieve, NULL, tcp_recieve_thread, (void *)j);
        }

        tcp_sniff_fun(serverIp, serverPort, sniffCount, sniffTime);
        check_tcp_connect_status();
    }
    if(sniffType == 1)
    {
        http_sniff_fun(serverIp, serverPort, sniffCount, sniffTime);
    }
    if(sniffType == 2)
    {
        https_sniff_fun(serverIp, serverPort, sniffCount, sniffTime);
    }
    if(sniffType == 3)
    {
		dns_sniff_fun(serverIp, sniffCount, sniffTime);
    }
    
    while(1)
    {
		sleep(5);
    }
}
