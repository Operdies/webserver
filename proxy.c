/* Nice little proxy server
 * TODO:
 * 1. Collect interesting metrics -- determine what is interesting
 * 2. High cpu utilization bug in handle_client -- observed in -O3 build
 */


#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "proxy.h"

/* static */ void unescape_string(char *str, int n);
static struct header_list *get_header(struct header_list *headers, char *name);
static void proxy_log(int loglevel, char *fmt, ...);

#include "config.h"

void static_file_handler(struct handler *handler, struct client_options opts) {
  char *file = handler->file.path;
  char *host = get_header(opts.headers, "Host:")->line + strlen("Host: ");
  proxy_log(DEBUG, "Static server %.*s -> %s\n", strlen(host) - 2, host, file);

  int filefd = open(file, O_RDONLY);
  if (filefd == -1) {
    proxy_log(ERROR, "Error opening %s:", file);
    return;
  }

  size_t fs = lseek(filefd, 0, SEEK_END);
  lseek(filefd, 0, SEEK_SET);

  dprintf(opts.fd, "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\n", fs);
  for (struct header_list *h = handler->additional_headers; h; h = h->next) {
    dprintf(opts.fd, "%s\r\n", h->line);
  }
  dprintf(opts.fd, "\r\n");

  proxy_log(DEBUG, "Serve %zu bytes", fs);

  off_t *offset = NULL;
  size_t sent = 0;
  for (; sent < fs;) {
    int written = sendfile(opts.fd, filefd, offset, fs);
    proxy_log(DEBUG, "sendfile %d mB", written / 1000000);
    if (written == -1) {
      proxy_log(ERROR, "sendfile:");
      break;
    }
    sent += written;
  }
  close(filefd);
}

void redirect_handler(struct handler *handler, struct client_options opts) {
  char *address = handler->redirect.host;
  char *host = get_header(opts.headers, "Host:")->line + strlen("Host: ");
  int portno = handler->redirect.port;
  proxy_log(DEBUG, "Redirect %.*s -> %s:%d\n", strlen(host) - 2, host, address,
            portno);
  dprintf(opts.fd,
          "HTTP/1.0 301 OK\r\n"
          "Location: http://%s:%d\r\n\r\n",
          address, portno);
}

void proxy_pass_handler(struct handler *handler, struct client_options opts) {
  char *address = handler->proxy.host;
  char *host = get_header(opts.headers, "Host:")->line + strlen("Host: ");
  int sockfd = 0;
  int portno = handler->proxy.port;
  proxy_log(DEBUG, "Proxy %.*s -> %s:%d\n", strlen(host) - 2, host, address,
            portno);
  struct sockaddr_in serv_addr = {.sin_family = AF_INET,
                                  .sin_port = htons(portno)};
  struct hostent *server;

  server = gethostbyname(address);
  memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    goto server_error;
  }

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    goto server_error;
  }

  { /* forward headers */
    FILE *f = fdopen(dup(sockfd), "w");
    struct header_list *h;
    h = opts.headers;
    for (; h; h = h->next) {
      if (startswith(h->line, "Host:")) {
        fprintf(f, "Host: %s:%d\r\n", address, portno);
      } else {
        fprintf(f, "%s", h->line);
      }
    }
    fprintf(f, "\r\n");
    fclose(f);
  }

  const int readfd = 0;
  const int writefd = 1;
  int pipefds[2];

  if (-1 == pipe(pipefds)) {
    proxy_log(ERROR, "pipe:");
    goto server_error;
  }

  struct pollfd fds[2] = {
      {.fd = sockfd, .events = POLLIN},
      {.fd = opts.fd, .events = POLLIN},
  };

  for (;;) {
    int n = poll(fds, 2, -1);
    if (n == -1) {
      perror("poll");
      break;
    }

    if (fds[0].revents & POLLIN) {
      int rc = splice(fds[0].fd, NULL, pipefds[writefd], NULL,
                      PIPE_SPLICE_COUNT, SPLICE_F_MOVE | SPLICE_F_MORE);
      int wc = splice(pipefds[readfd], NULL, fds[1].fd, NULL, rc,
                      SPLICE_F_MOVE | SPLICE_F_MORE);
      assert(rc == wc);
      proxy_log(DIAG, "splice out %d", wc);
      if (rc <= 0) {
        break;
      }
    }

    if (fds[1].revents & POLLIN) {
      int rc = splice(fds[1].fd, NULL, pipefds[writefd], NULL,
                      PIPE_SPLICE_COUNT, SPLICE_F_MOVE | SPLICE_F_MORE);
      int wc = splice(pipefds[readfd], NULL, fds[0].fd, NULL, rc,
                      SPLICE_F_MOVE | SPLICE_F_MORE);
      assert(rc == wc);
      proxy_log(DIAG, "splice in  %d", wc);
      if (rc <= 0) {
        break;
      }
    }
  }

  close(sockfd);
  close(pipefds[readfd]);
  close(pipefds[writefd]);
  return;

server_error:
  if (sockfd > 0)
    close(sockfd);
  proxy_log(ERROR, "Proxy error:");
  char payload[] = "HTTP/1.0 501\r\n\r\n";
  write(opts.fd, payload, strlen(payload));
  return;
}

void unescape_string(char *str, int n) {
  char lookup[] = {
      ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,
      ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,  ['a'] = 10, ['A'] = 10,
      ['b'] = 11, ['B'] = 11, ['c'] = 12, ['C'] = 12, ['d'] = 13, ['D'] = 13,
      ['e'] = 14, ['E'] = 14, ['f'] = 15, ['F'] = 15,
  };

  if (str == NULL)
    return;
  if (n <= 0)
    n = strlen(str);

  int cursor = 0, i = 0;
  for (; i < n; i++) {
    if (str[i] == '%') {
      if ((i+2) >= n) {
        break;
      }
      int c1 = str[i + 1];
      int c2 = str[i + 2];
      char actual = (lookup[c1] << 4) | (lookup[c2]);
      i += 2;
      str[cursor++] = actual;
    } else {
      str[cursor++] = str[i];
    }
  }
  str[cursor] = 0;
}

struct header_list *get_header(struct header_list *headers, char *name) {
  int n = strlen(name);
  for (; headers; headers = headers->next) {
    if (0 == strncasecmp(headers->line, name, n))
      return headers;
  }
  return NULL;
}

void proxy_log(int loglevel, char *fmt, ...) {
  char *log_headers[] = {[WARN] = "\033[1;30;43m",  [DIAG] = "\033[1;30;47m",
                         [DEBUG] = "\033[1;30;46m", [INFO] = "\033[1;30;44m",
                         [ERROR] = "\033[1;30;41m", [FATAL] = "\033[1;30;41m"};

  char *log_colors[] = {
      [DEBUG] = "\033[1;36m", [DIAG] = "\033[1;37m",  [INFO] = "\033[1;34m",
      [WARN] = "\033[1;33m",  [ERROR] = "\033[1;31m", [FATAL] = "\033[1;31m"};
  char *reset_color = "\033[0m";

  if (loglevel > LOGLEVEL)
    return;
  char *levels[] = {
      [DEBUG] = "DEBUG", [INFO] = "INFO ", [WARN] = "WARN ",
      [ERROR] = "ERROR", [DIAG] = "DIAG ", [FATAL] = "FATAL",
  };

  char *b;
  size_t bs;
  FILE *f = open_memstream(&b, &bs);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(f, fmt, ap);
  va_end(ap);
  fclose(f);

  time_t rawtime;
  struct tm *timeinfo;

  time(&rawtime);
  timeinfo = localtime(&rawtime);

  char timebuf[100] = {0};
  strftime(timebuf, sizeof(timebuf), "%H:%M:%S", timeinfo);
  printf("\r%s[%s %s]%s ", log_headers[loglevel], timebuf, levels[loglevel],
         reset_color);

  if (bs) {
    char last = b[bs - 1];
    printf("%s%s%s ", log_colors[loglevel], b, reset_color);
    fflush(stdout);
    if (last == ':') {
      perror(NULL);
    } else if (last != '\n') {
      puts("");
    }
  }

  free(b);

  if (loglevel == FATAL)
    exit(1);
}

void free_headers(struct header_list *h) {
  if (h) {
    free_headers(h->next);
    free(h->line);
    free(h);
  }
}

void handle_client(int clientfd) {
  int n_read;

  FILE *f = fdopen(clientfd, "rw");
  char *line = NULL;
  size_t len = 0;

  struct header_list *headers = NULL, *tail = NULL;
  while ((n_read = getline(&line, &len, f)) != -1) {
    uint16_t signature = *(uint16_t *)line;
    if (signature == 0x316) {
      // https -- just reject the connection and move on.
      proxy_log(DEBUG, "Rejecting https request.");
      goto cleanup;
    }

    if (startswith(line, "GET ")) {
      proxy_log(DEBUG, "%s", line);
    }

    if (strcmp(line, "\r\n") == 0)
      break;
    proxy_log(DIAG, "[Header] %s", line);
    struct header_list *header = calloc(1, sizeof(*headers));
    char *l = line;

    header->line = l;
    line = NULL;
    len = 0;

    if (headers == NULL)
      headers = tail = header;
    tail->next = header;
    tail = header;
  }

  struct header_list *host = get_header(headers, "Host");
  if (!host) {
    fprintf(stderr, "No host header found (?)\n");
  } else {
    char *hostline = host->line + strlen("Host: ");
    int subdomain_len = 0;
    char *period = strchr(hostline, '.');
    if (period)
      subdomain_len = period - hostline;
    struct client_options opts = {
        .fd = clientfd,
        .headers = headers,
    };
    for (int i = 0; i < LENGTH(handlers); i++) {
      struct handler *h = &handlers[i];
      if (h->subdomain && subdomain_len &&
          strlen(h->subdomain) == subdomain_len &&
          strncmp(hostline, h->subdomain, subdomain_len) == 0) {
        proxy_log(DEBUG, "Host %.*s matched handler %s", strlen(hostline) - 2,
                  hostline, h->subdomain);
        h->handler(h, opts);
        break;
      } else if (h->subdomain == NULL) {
        proxy_log(DEBUG, "Fallback handler matched");
        h->handler(h, opts);
        break;
      }
    }
  }

cleanup:
  free_headers(headers);
  fclose(f);
  close(clientfd);
}

void *handle_client_thread(void *arg) {
  int clientfd = (int)((uint64_t)arg);
  handle_client(clientfd);
  return NULL;
}

int main(int argc, char *argv[]) {
  struct sockaddr_in saddr = {.sin_family = AF_INET,
                              .sin_addr.s_addr = INADDR_ANY,
                              .sin_port = htons(SERVER_PORT)};
  struct sockaddr_in caddr = {0};
  socklen_t csize = sizeof(caddr);
  int sockfd, clientfd;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    proxy_log(FATAL, "socket:");

  int reuseaddr = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                 sizeof(reuseaddr)) == -1)
    proxy_log(FATAL, "setsockopt:");

  if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    proxy_log(FATAL, "bind:");

  listen(sockfd, BACKLOGSIZE);
  for (;;) {
    clientfd = accept(sockfd, (struct sockaddr *)&caddr, &csize);
    proxy_log(DEBUG, "Accepted connection.");
    uint64_t fd = clientfd;
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, handle_client_thread, (void *)fd);
    pthread_detach(thread_id);
  }
  close(sockfd);
  return 0;
}

/* Example of how one might serve files */
// void file_download_handler(struct handler *handler,
//                            struct client_options opts) {
//   dprintf(opts.fd,
//           "HTTP/1.0 200 OK\r\n"
//           "Content-Length: %zu\r\n"
//           "Content-Disposition: attachment; filename=\"file.txt\"\r\n"
//           "\r\n",
//           filesize);
// }
