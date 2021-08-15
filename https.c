/* SOCKET TIME */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#include <netdb.h>
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

const char* DEST_IP = "61.135.169.121";


const int DEST_PORT = 443;


const char* REQUEST = "GET / HTTP/1.1\nHost: www.baidu.com\r\n\r\n";

int main(int argc, char* argv[]) {


  SSL_load_error_strings();
  SSL_library_init();
  SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method());
  

  int sockfd = socket(PF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    perror("Unable to create socket");
    return 1;
  }

  int flags = fcntl(sockfd, F_GETFL, 0);
  unsigned long ul = 1;

  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(DEST_PORT);
  dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);
  memset(&(dest_addr.sin_zero), '\0', 8);

  int status = connect(sockfd, (struct sockaddr*) &dest_addr, sizeof(struct sockaddr_in));
  if (status == -1) {
    perror("Unable to connect to the server");
    close(sockfd);
    return 1;
  }


  SSL *conn = SSL_new(ssl_ctx);
  SSL_set_fd(conn, sockfd);
  SSL_connect(conn);

  ssize_t sendsize = SSL_write(conn, REQUEST, strlen(REQUEST));
  if (sendsize == -1) {
    perror("Unable to send to the server");
    {
      char buf[256];
      u_long err;

      while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        printf("*** %s\n", buf);
      }
    }
    SSL_shutdown(conn);
    SSL_free(conn);
    close(sockfd);
    return 1;
  }

  int len; 
  int count; 
  ssize_t recsize;

  while (1) 
  {

    const int RESPONSE_SIZE = 512;
    char response[RESPONSE_SIZE];
    recsize = SSL_read(conn, response, RESPONSE_SIZE-1);
    if (recsize == -1) {
      perror("Unable to send to the server");
      SSL_shutdown(conn);
      SSL_free(conn);
      close(sockfd);
      return 1;
    }
    
    response[recsize] = '\0';
    
    write(STDOUT_FILENO, response, recsize);
	printf("recsize: \n", recsize);   
	
    recsize = 0; 
    if (recsize < 0)
    {
		SSL_shutdown(conn);
		SSL_free(conn);
		close(sockfd);
		return 0;
    }

  }

  SSL_shutdown(conn);
  SSL_free(conn);  

  close(sockfd);

  return 0;
}
