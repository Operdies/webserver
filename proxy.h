#ifndef PROXY_H

#define PIPE_SPLICE_COUNT (1 << 16)
#define _FILE_OFFSET_BITS 64
#define LENGTH(x) (sizeof(x) / sizeof((x)[0]))
#define BACKLOGSIZE 20
#define startswith(str, val) (strncmp(str, val, sizeof(val) - 1) == 0)

enum PROXY_LOG_LEVEL { FATAL = 1, ERROR, WARN, INFO, DEBUG, DIAG };

struct header_list;
struct header_list {
  char *line;
  struct header_list *next;
};

struct client_options {
  struct header_list *headers;
  int fd;
};

struct handler;

typedef void(handlerfunc)(struct handler *handler, struct client_options opts);

struct handler {
  char *subdomain;
  handlerfunc *handler;
  union {
    // Proxy scenario
    struct {
      char *host;
      int port;
    } proxy;
    struct {
      char *host;
      int port;
    } redirect;
    // Static file serving scenario
    struct {
      char *path;
    } file;
  };
  struct header_list *additional_headers;
};

void redirect_handler(struct handler *handler, struct client_options opts);
void static_file_handler(struct handler *handler, struct client_options opts);
void file_download_handler(struct handler *handler, struct client_options opts);
void proxy_pass_handler(struct handler *handler, struct client_options opts);

#define PROXY_H
#endif