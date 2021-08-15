#include <sys/epoll.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <fcntl.h>  
#include <arpa/inet.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <pthread.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <string.h>
#include <netinet/tcp.h>
#include<linux/if_ether.h>


int        m_iEpollFd;
#define _MAX_SOCKFD_COUNT 65535
int        m_isock;
pthread_t  m_ListenThreadId;

#define false		  0
#define true		  1

void Run()
{
    struct sockaddr_in client;
    while ( true )
    {
		int i;
        struct epoll_event    events[_MAX_SOCKFD_COUNT];
        int nfds = epoll_wait( m_iEpollFd, events,  _MAX_SOCKFD_COUNT, -1 );
        for(i = 0; i < nfds; i++)
        {
            int client_socket = events[i].data.fd;
			char buffer[1024];//每次收发的字节数小于1024字节
			memset(buffer, 0, 1024);
			if(events[i].events & EPOLLIN)//监听到读事件，接收数据
			{
				/*int rev_size = recv(events[i].data.fd,buffer, 1024,0);
				if( rev_size <= 0 )
				{
					printf("recv error :recv size %d\n", rev_size);
					struct epoll_event event_del;
					event_del.data.fd = events[i].data.fd;
					event_del.events = 0;
					epoll_ctl(m_iEpollFd, EPOLL_CTL_DEL, event_del.data.fd, &event_del);
				}
				else
				{
					printf("Terminal Received Msg Content:%s\n",buffer);
					struct epoll_event    ev;
					ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
					ev.data.fd = client_socket;//记录socket句柄
					epoll_ctl(m_iEpollFd, EPOLL_CTL_MOD, client_socket, &ev);
				}*/
				int len = sizeof(client);
				int num = recvfrom(events[i].data.fd, buffer, 1024, 0, (struct sockaddr *)&client, &len);
				if (num < 0)
				{
					perror("recvfrom() error\n");
					struct epoll_event event_del;
					event_del.data.fd = events[i].data.fd;
					event_del.events = 0;
					epoll_ctl(m_iEpollFd, EPOLL_CTL_DEL, event_del.data.fd, &event_del);
				}
				else
				{
					printf("Terminal Received Msg Content:%s\n",buffer);
					struct sockaddr_in source, dest;
					struct iphdr *ip1 = (struct iphdr *)( buffer );
					printf("Version : %d\n",(unsigned int)ip1->version);
					printf("Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip1->ihl,((unsigned int)(ip1->ihl))*4);
					printf("Type Of Service : %d\n",(unsigned int)ip1->tos);
					printf("Total Length : %d Bytes\n",ntohs(ip1->tot_len));
					printf("Identification : %d\n",ntohs(ip1->id));
					printf("Time To Live : %d\n",(unsigned int)ip1->ttl);
					printf("Protocol : %d\n",(unsigned int)ip1->protocol);
					printf("Header Checksum : %d\n",ntohs(ip1->check));
		 
					struct epoll_event    ev;
					ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
					ev.data.fd = client_socket;//记录socket句柄
					epoll_ctl(m_iEpollFd, EPOLL_CTL_MOD, client_socket, &ev);
				}
			}
			else if(events[i].events & EPOLLOUT)//监听到写事件，发送数据
			{
				char sendbuff[1024];
				sprintf(sendbuff, "Hello, client fd: %d\n", client_socket);
				int sendsize = send(client_socket, sendbuff, strlen(sendbuff)+1, MSG_NOSIGNAL);
				if(sendsize <= 0)
				{
					struct epoll_event event_del;
					event_del.data.fd = events[i].data.fd;
					event_del.events = 0;
					epoll_ctl(m_iEpollFd, EPOLL_CTL_DEL, event_del.data.fd, &event_del);
				}
				else
				{
					printf("Server reply msg ok! buffer: %s\n", sendbuff);
					struct epoll_event    ev;
					ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
					ev.data.fd = client_socket;//记录socket句柄
					epoll_ctl(m_iEpollFd, EPOLL_CTL_MOD, client_socket, &ev);
				}
			}
			else
			{  
				printf("EPOLL ERROR\n");
				epoll_ctl(m_iEpollFd, EPOLL_CTL_DEL, events[i].data.fd, &events[i]);
			}
		}
    }
}

void  ListenThread( void* lpVoid )
{
    struct sockaddr_in remote_addr;
    int len = sizeof (remote_addr);
    char buf[1024] = "";
    while(true)
    {
        int client_socket = accept(m_isock, (struct sockaddr *)&remote_addr,(socklen_t*)&len );
        if(client_socket < 0)
        {
            printf("Server Accept失败!, client_socket: %d\n", client_socket);
            continue;
        }
        else
        {
            struct epoll_event    ev;
            ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
            ev.data.fd = client_socket;     //记录socket句柄
            epoll_ctl(m_iEpollFd, EPOLL_CTL_ADD, client_socket, &ev);
        }
        /*int num = recvfrom(m_isock, buf, 1024, 0, (struct sockaddr *)&remote_addr, &len);
        if (num < 0)
        {
            perror("recvfrom() error\n");
            exit(1);
        }
		else
		{
			struct sockaddr_in source, dest;
			struct iphdr *ip1 = (struct iphdr *)( buf );
			printf("Version : %d\n",(unsigned int)ip1->version);
			printf("Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)ip1->ihl,((unsigned int)(ip1->ihl))*4);
			printf("Type Of Service : %d\n",(unsigned int)ip1->tos);
			printf("Total Length : %d Bytes\n",ntohs(ip1->tot_len));
			printf("Identification : %d\n",ntohs(ip1->id));
			printf("Time To Live : %d\n",(unsigned int)ip1->ttl);
			printf("Protocol : %d\n",(unsigned int)ip1->protocol);
			printf("Header Checksum : %d\n",ntohs(ip1->check));
	
			struct epoll_event    ev;
			ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
			ev.data.fd = m_isock;//client_socket;     //记录socket句柄
			epoll_ctl(m_iEpollFd, EPOLL_CTL_ADD, m_isock, &ev);
		}*/
    }
}

int InitServer(const char* pIp, int iPort)
{
    m_iEpollFd = epoll_create(_MAX_SOCKFD_COUNT);

    //设置非阻塞模式
    int opts = O_NONBLOCK;
    if(fcntl(m_iEpollFd,F_SETFL,opts)<0)
    {
        printf("设置非阻塞模式失败!\n");
        return 0;
    }

    /*m_isock = socket(AF_INET,SOCK_STREAM,0);
    if(0 > m_isock)
    {
        printf("socket error!\n");
        return 0;
    }*/
    if((m_isock = socket(AF_INET,SOCK_RAW, IPPROTO_TCP)) < 0)
    {
        perror("unknow protocol tcp");
        exit(2);
    }

    struct sockaddr_in listen_addr;
    listen_addr.sin_family=AF_INET;
    listen_addr.sin_port=htons ( iPort );
    listen_addr.sin_addr.s_addr=htonl(INADDR_ANY);
    listen_addr.sin_addr.s_addr=inet_addr(pIp);

	//int ireuseadd_on = 1;//支持端口复用
	//setsockopt(m_isock, SOL_SOCKET, SO_REUSEADDR, &ireuseadd_on, sizeof(ireuseadd_on) );

    if(bind(m_isock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) !=0)
    {
        printf("bind error\n");
        return 0;
    }

	/*if(listen(m_isock, 20) < 0)
	{
		printf("listen error!\n");
		return 0;
	}
	else
	{
		printf("服务端监听中...\n");
	}
	*/
    //监听线程，此线程负责接收客户端连接，加入到epoll中
    /*if(pthread_create(&m_ListenThreadId, 0,(void *(*)(void *)) ListenThread, NULL) != 0)
    {
        printf("Server 监听线程创建失败!!!");
    }*/
}

int main()
{
    InitServer("172.168.1.13", 2345);
    Run();
}
