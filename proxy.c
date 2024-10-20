/* Nice little proxy server
 * TODO:
 * 1. Collect interesting metrics -- determine what is interesting
 * 2. High cpu utilization bug in handle_client -- observed in -O3 build
 */

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#include "proxy.h"
#include <assert.h>
#include <bits/time.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* static */ void unescape_string(char *str, int n);
static struct header_list *get_header(struct header_list *headers, char *name);
static void proxy_log(int loglevel, char *fmt, ...);

#include "config.h"

static unsigned char jellyfin_server_mac_address[] = {0xe0, 0x3f, 0x49,
                                                      0xb4, 0x63, 0xe9};
#define jellyfin_server_address "192.168.0.111"
static char server_address2[] = {192, 168, 0, 111};
#define msleep(x) (usleep((x) * 1000))

static void send_magic_packet(unsigned char mac[6]) {
  proxy_log(DEBUG, "Sending magic packet");
  unsigned char magic_packet[102];
  int idx;

  // Build magic packet
  for (idx = 0; idx < 6; idx++)
    magic_packet[idx] = 0xff;
  for (; idx < sizeof(magic_packet); idx++)
    magic_packet[idx] = mac[idx % 6];

  struct sockaddr_in s = {
      .sin_family = AF_INET,
      .sin_port = htons(4000),
      .sin_addr.s_addr = htonl(INADDR_BROADCAST),
  };

  int bcast_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (bcast_sock == -1) {
    proxy_log(ERROR, "socket:");
    return;
  }

  int broadcastEnable = 1;
  if (-1 == setsockopt(bcast_sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable,
                       sizeof(broadcastEnable))) {
    proxy_log(ERROR, "enable broadcast:");
    goto error;
  }

  if (-1 == connect(bcast_sock, (struct sockaddr *)&s, sizeof(s))) {
    proxy_log(ERROR, "connect:");
    goto error;
  }

  int written = write(bcast_sock, magic_packet, sizeof(magic_packet));
  if (written != sizeof(magic_packet)) {
    proxy_log(ERROR, "write:");
  }
error:
  close(bcast_sock);
}

static int send_suspend_signal() {
  int sockfd;
  int portno = 1337;
  struct sockaddr_in serv_addr = {.sin_family = AF_INET,
                                  .sin_addr.s_addr =
                                      *(uint32_t *)server_address2,
                                  .sin_port = htons(portno)};
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    proxy_log(ERROR, "socket:");
    return 0;
  }
  if (-1 == connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) {
    close(sockfd);
    // The machine is already off, probably?
    return 0;
  } else {
    char buf[100];
    int n = read(sockfd, &buf, 100);
    proxy_log(DEBUG, "suspend: %.*s", n, buf);
  }
  close(sockfd);
  return 1;
}

static struct timespec last_active = {0};
static int asleep = -1;
static void on_activity() { clock_gettime(CLOCK_REALTIME, &last_active); }

static int inhibit_suspend() {
  // TODO: Inhibit suspend if qbittorrent is currently downloading.
  return 0;
}

#define IDLE_SUSPEND_MINUTES (30)
static void *suspend_if_inactive(void *a) {
  struct timespec now = {0};
  clock_gettime(CLOCK_REALTIME, &now);
  uint64_t inactive_time = now.tv_sec - last_active.tv_sec;
  int do_suspend = inactive_time > (IDLE_SUSPEND_MINUTES * 60) && !inhibit_suspend();
  if (do_suspend) {
    int did_suspend = send_suspend_signal();
    if (did_suspend)
      proxy_log(DEBUG, "Sent suspend signal to server.");
    // if the call failed, assume it failed because the system was already
    // suspended?
    asleep = 1;
  }

  return NULL;
}

void dummy_handler(struct handler *handler, struct client_options opts) {
  dprintf(opts.conn->fd, "HTTP/1.0 200 OK\r\n\r\n");
}

void static_file_handler(struct handler *handler, struct client_options opts) {
  char *file = handler->file.path;
  char *host = get_header(opts.headers, "Host:")->line + strlen("Host: ");
  proxy_log(DEBUG, "Static server %.*s -> %s", strlen(host) - 2, host, file);

  int filefd = open(file, O_RDONLY);
  if (filefd == -1) {
    proxy_log(ERROR, "Error opening %s:", file);
    return;
  }

  size_t fs = lseek(filefd, 0, SEEK_END);
  lseek(filefd, 0, SEEK_SET);

  dprintf(opts.conn->fd, "HTTP/1.0 200 OK\r\nContent-Length: %zu\r\n", fs);
  for (struct header_list *h = handler->additional_headers; h; h = h->next) {
    dprintf(opts.conn->fd, "%s\r\n", h->line);
  }
  dprintf(opts.conn->fd, "\r\n");

  proxy_log(DEBUG, "Serve %zu bytes", fs);

  off_t *offset = NULL;
  size_t sent = 0;
  for (; sent < fs;) {
    int written = sendfile(opts.conn->fd, filefd, offset, fs);
    if (written == -1) {
      // EPIPE is expected if the client disconnects
      proxy_log(errno == EPIPE ? DEBUG : ERROR, "sendfile:", errno);
      break;
    }
    proxy_log(DEBUG, "sendfile %d mB", written / 1000000);
    sent += written;
  }
  close(filefd);
}

void redirect_handler(struct handler *handler, struct client_options opts) {
  char *address = handler->redirect.host;
  char *host = get_header(opts.headers, "Host:")->line + strlen("Host: ");
  int portno = handler->redirect.port;
  proxy_log(DEBUG, "Redirect %.*s -> %s:%d", strlen(host) - 2, host, address,
            portno);
  dprintf(opts.conn->fd,
          "HTTP/1.0 301 OK\r\n"
          "Location: http://%s:%d\r\n\r\n",
          address, portno);
}


void proxy_pass_handler(struct handler *handler, struct client_options opts) {
  char *address = handler->proxy.host;
  char *host = get_header(opts.headers, "Host:")->line + strlen("Host: ");
  int sockfd = 0;
  int portno = handler->proxy.port;
  proxy_log(DEBUG, "Proxy %.*s -> %s:%d", strlen(host) - 2, host, address,
            portno);
  struct sockaddr_in serv_addr = {.sin_family = AF_INET,
                                  .sin_port = htons(portno)};
  struct hostent *server;

  server = gethostbyname(address);
  memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    proxy_log(ERROR, "socket:");
    goto server_error;
  }

  on_activity();
  int connect_retries = 5;
  int connected;
  for (int i = 0; i < connect_retries; i++) {
    connected =
        connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0;
    if (connected)
      break;
    proxy_log(ERROR, "(%d) connect:", i);
    send_magic_packet(jellyfin_server_mac_address);
    msleep(2000);
  }

  if (!connected) {
    dprintf(opts.conn->fd, "HTTP/1.1 503 Service Unavailable\r\n\r\n");
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
      {.fd = opts.conn->fd, .events = POLLIN},
  };

  for (;;) {
    on_activity();
    int n = poll(fds, 2, -1);
    if (n == -1) {
      proxy_log(ERROR, "poll");
      break;
    }

    if (fds[0].revents & POLLIN) {
      int rc = splice(fds[0].fd, NULL, pipefds[writefd], NULL,
                      PIPE_SPLICE_COUNT, SPLICE_F_MOVE | SPLICE_F_MORE);
      if (rc == -1) proxy_log(ERROR, "splice read server:");
      if (rc <= 0) break;
      int wc = splice(pipefds[readfd], NULL, fds[1].fd, NULL, rc,
                      SPLICE_F_MOVE | SPLICE_F_MORE);
      if (wc == -1) proxy_log(ERROR, "splice write server:");
      if (wc <= 0) break;
    }

    if (fds[1].revents & POLLIN) {
      int rc = splice(fds[1].fd, NULL, pipefds[writefd], NULL,
                      PIPE_SPLICE_COUNT, SPLICE_F_MOVE | SPLICE_F_MORE);
      if (rc == -1) proxy_log(ERROR, "splice read client:");
      if (rc <= 0) break;
      int wc = splice(pipefds[readfd], NULL, fds[0].fd, NULL, rc,
                      SPLICE_F_MOVE | SPLICE_F_MORE);
      if (wc == -1) proxy_log(ERROR, "splice write client:");
      if (wc <= 0) break;
    }
  }

  close(sockfd);
  close(pipefds[readfd]);
  close(pipefds[writefd]);
  return;

server_error:
  if (sockfd > 0)
    close(sockfd);
  char payload[] = "HTTP/1.0 501\r\n\r\n";
  write(opts.conn->fd, payload, strlen(payload));
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
      if ((i + 2) >= n) {
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


static FILE *logfile = NULL;
// Leave some space for rolling
static char logfilename[sizeof(LOGFILE) + 20];
static int logfilecount = 0;

static void roll_logfile() {
  if (logfile)
    fclose(logfile);
  sprintf(logfilename, "%s.%d.%d", LOGFILE, getpid(), logfilecount);
  logfilecount++;
  logfile = fopen(logfilename, "w");
}

void proxy_log(int loglevel, char *fmt, ...) {
  static char *levels[] = {
    [DEBUG] = "DEBUG", [INFO] = " INFO", [WARN] = " WARN",
    [ERROR] = "ERROR", [DIAG] = " DIAG", [FATAL] = "FATAL",
  };

  if (loglevel > LOGLEVEL && loglevel != FATAL)
    return;

  flockfile(logfile);

  if (ftell(logfile) > MAXLOGSIZE) {
    fprintf(logfile, "Rolling logfile to %s.%d\n", LOGFILE, logfilecount);
    roll_logfile();
  }

  va_list ap;
  va_start(ap, fmt);

  time_t rawtime;
  struct tm *timeinfo;
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  char timebuf[100] = {0};
  strftime(timebuf, sizeof(timebuf), "%H:%M:%S", timeinfo);
  fprintf(logfile, "[%s %s] ", timebuf, levels[loglevel]);
  vfprintf(logfile, fmt, ap);

  va_end(ap);

  if (fmt && fmt[strlen(fmt)-1] == ':') {
    fprintf(logfile, " %s", strerror(errno));
  }

  fprintf(logfile, "\n");
  fflush(logfile);
  funlockfile(logfile);

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

void handle_client(struct client_connection *conn) {
  int n_read;

  FILE *f = fdopen(dup(conn->fd), "r");
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
    int headerlen = strchrnul(line, '\r') - line;
    proxy_log(DIAG, "[Header] %.*s", headerlen, line);
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
    proxy_log(ERROR, "No host header found (?)");
  } else {
    char *hostline = host->line + strlen("Host: ");
    int subdomain_len = 0;
    char *period = strchr(hostline, '.');
    if (!period) period = strchrnul(hostline, '\r');
    subdomain_len = period - hostline;
    struct client_options opts = {
        .headers = headers,
        .conn = conn,
    };
    int handled = 0;
    for (int i = 0; i < LENGTH(handlers); i++) {
      struct handler *h = &handlers[i];
      if (h->subdomain && subdomain_len &&
          strlen(h->subdomain) == subdomain_len &&
          strncmp(hostline, h->subdomain, subdomain_len) == 0) {
        proxy_log(DEBUG, "Host %.*s matched handler %s", strlen(hostline) - 2,
                  hostline, h->subdomain);
        h->handler(h, opts);
        handled = 1;
        break;
      } else if (h->subdomain == NULL) {
        proxy_log(DEBUG, "Fallback handler matched");
        h->handler(h, opts);
        break;
        handled = 1;
      }
    }
    if (!handled) proxy_log(ERROR, "Request for host '%s' not handled.", hostline);
  }

cleanup:
  free_headers(headers);
  fclose(f);
  close(conn->fd);
  free(conn);
}

void *handle_client_thread(void *arg) {
  handle_client((struct client_connection*)arg);
  return NULL;
}

static void sigpipe_handler(int signum) {
  proxy_log(DEBUG, "Pipe handler triggered (%d).", signum);
}

int main(int argc, char *argv[]) {
  roll_logfile();
  proxy_log(INFO, "Server started!");
  clock_gettime(CLOCK_REALTIME, &last_active);
  struct sigaction sa = {0};
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = sigpipe_handler;
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGPIPE, &sa, NULL) == -1)
    proxy_log(FATAL, "sigaction:");

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
  struct pollfd pfd = {.fd = sockfd, .events = POLLIN};
  for (;;) {
    int n = poll(&pfd, 1, 10000);
    if (n > 0) {
      clientfd = accept(sockfd, (struct sockaddr *)&caddr, &csize);
      uint32_t ca = caddr.sin_addr.s_addr;
      proxy_log(DEBUG, "Accepted connection from %d.%d.%d.%d", ca & 0xff, ca >> 8 & 0xff, ca >> 16 & 0xff, ca >> 24 & 0xff);
      pthread_t thread_id;
      struct client_connection *conn = calloc(1, sizeof(*conn));
      conn->fd = clientfd;
      conn->client = caddr;
      if (pthread_create(&thread_id, NULL, handle_client_thread, conn) == 0) {
        pthread_detach(thread_id);
      } else {
        proxy_log(FATAL, "Unable to spawn thread:");
      }
    } else {
      pthread_t thread_id;
      if (pthread_create(&thread_id, NULL, suspend_if_inactive, 0) == 0) {
        pthread_detach(thread_id);
      } else {
        proxy_log(FATAL, "Unable to spawn thread:");
      }
    }
  }
  close(sockfd);
  return 0;
}
