#include <sys/socket.h>
#include <arpa/inet.h>

#include "remote_fork.h"

void handle_client(int sock) {
  printf("Receiving process\n");
  FILE* stream = fdopen(sock, "rb");
  if (stream == NULL) {
    raise_error("unable to open stream with fdopen()");
  }
  
  pid_t child = receive_fork(stream, sock); 
  printf("received child to pid %d and passed to TCP %d\n", child, sock);
  int status = wait_for_exit(child);
  printf("child exited with status %d\n", status);
  fclose(stream);
}

int main() {
  int s;
  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    raise_error("error opening socket");
  }

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(8081);
  server.sin_addr.s_addr = INADDR_ANY;

  if (bind(s, (struct sockaddr*) &server, sizeof(server)) < 0) {
    raise_error("error binding socket");
  }

  __uint32_t namelen;
  int ns;
  struct sockaddr_in client;
  // for (;;) {
  if (listen(s, 1) != 0) {
    raise_error("error listening");
  }
  
  namelen = sizeof(client);
  if ((ns = accept(s, (struct sockaddr *)&client, &namelen)) == -1) {
    raise_error("error accepting");
  }
  handle_client(ns);
  
  close(s);
  close(ns);
  return 0;
}
