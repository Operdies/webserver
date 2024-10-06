#include "proxy.h"
#include <stddef.h>

#ifndef SERVER_PORT
#define SERVER_PORT 1337
#endif

#ifndef LOGLEVEL
#define LOGLEVEL DEBUG
#endif

#define HEADER(x, n) (&(struct header_list){.line = x, .next = n})

struct handler handlers[] = {
    /* proxy communication between client and server */
    {
        .subdomain = "proxy-example",
        .handler = proxy_pass_handler,
        .proxy =
            {
                .host = "192.168.0.111",
                .port = 1337,
            },
    },
    /* redirect to new address */
    {
        .subdomain = "redirect-example",
        .handler = redirect_handler,
        .redirect =
            {
                .host = "192.168.0.111",
                .port = 8080,
            },
    },
    /* serve a file */
    {
        .subdomain = "download",
        .handler = static_file_handler,
        .file = {.path = "/path/to/filename.txt"},
        .additional_headers =
            HEADER("Content-Disposition: attachment;filename=filename.txt",
                   HEADER("Content-Type: text/plain;charset=UTF-8", NULL)),
    },
    /* fallback -- server a static index */
    {
        .handler = static_file_handler,
        .file = {.path = "/path/to/index.html"},
    },
};
