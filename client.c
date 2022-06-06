#include <sys/socket.h>
#include <arpa/inet.h>

#include "remote_fork.h"

int connect_to_tcp_server(char* server_addr) {
  int sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    raise_error("unable to create socket");
  }
  
  unsigned short port = 8081;
  struct sockaddr_in server;
  server.sin_addr.s_addr = inet_addr(server_addr);
  server.sin_family = AF_INET;
  server.sin_port = htons(port);

  if (connect(sock, (struct sockaddr*) &server, sizeof(server)) < 0) {
    raise_error("unable to connect to server");
  }

  return sock;
}

int main() {
  int foo = 103;
  printf("foo is %d", foo);

  int sock = connect_to_tcp_server("127.0.0.1");
  FILE* fout = fdopen(sock , "wb");
  Result res = remote_fork(fout);
  if (res.loc == Child) {
    printf("remote forked to %d\n", res.pid);
    printf("local var foo is %d\n", foo);
    exit(foo);
  } else {
    printf("remote forked to %s succeed\n", res.pid);
  }
  return 0;
}
