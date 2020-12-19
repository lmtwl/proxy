#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/acct.h>
#include <linux/netfilter_ipv4.h>
#include <assert.h>
#include <ctype.h>
#include <ifaddrs.h>
#include "list.h"
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

// #define log(fmt, arg...) printf("[proxy] %s:%d " fmt, __FUNCTION__, __LINE__, ##arg)

#define LOG(fmt...)                                    \
    do                                                 \
    {                                                  \
        fprintf(stderr, "%s %s ", __DATE__, __TIME__); \
        fprintf(stderr, ##fmt);                        \
    }                                                  \
    w

#define BUF_SIZE 16384

typedef enum
{
    TRUE = 1,
    FALSE = 0
} bool;

struct domainlist
{
    char *domain;
    struct list_head list;
};

uint16_t remote_port;
int BACKLOG = 20;
int bind_port = 88;
int remote_sock;
int server_sock, client_sock;
bool use_syslog = FALSE;
bool foreground = FALSE;
bool resolvstat = FALSE;
bool blacklist_file_stat = FALSE;
char *bind_addr;
char *blacklist_file;
char remote_host[INET6_ADDRSTRLEN];
// char *remote_host;
char *header_buffer = NULL;
struct domainlist blacklist;

int parse_options(int argc, char *argv[]);
int create_server_socket();
int create_connection();
int check_ipversion(char *address);
int send_data(int socket, char *buffer, int len);
int read_header(int fd, char *buffer);
int receive_data(int socket, char *buffer, int len);
int extract_http_header(const char *header, char **hostname);
int extract_https_header(unsigned char *bytes, size_t length, char **hostname);
int string_append(char **target_string, const char *text_to_append);
int acl(const char *path, struct domainlist *domainline);
int findlocalip(char *ip);
int hostname_to_ip(char *domain);

void sigchld_handler(int signal);
void sigterm_handler(int signal);
void plog(int priority, const char *format, ...);
void usage(void);
void server_loop();
void handle_client(int client_sock, struct sockaddr_storage client_addr);
void forward_data(int source_sock, int destination_sock);
static int simplematch(const char *pattern, const char *text);
char *trimwhitespace(char *str);

void plog(int priority, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);

    if (use_syslog)
        vsyslog(priority, format, ap);
    else
    {
        fprintf(stderr, "%s %s ", __DATE__, __TIME__);
        vfprintf(stderr, format, ap);
        fprintf(stderr, "\n");
    }
    va_end(ap);
}

void usage(void)
{
    printf("Usage:\n");
    printf(" -p <port number>  specifyed local listen port \n");
    printf(" -h <local ip> specifyed local listen ip\n");
    printf(" -r <blacklist file > specifyed local blacklist file\n");
    printf(" -s <use syslog>\n");
    printf(" -d <use daemon>\n");
    exit(8);
}

int hostname_to_ip(char *domain)
{
    // int i;
    struct hostent *he;
    struct in_addr **addr_list;
    memset(remote_host, 0, sizeof(remote_host));
    if ((he = gethostbyname(domain)) == NULL)
    {
        plog(LOG_CRIT, "gethostbyname is fail\n");
        return -1;
    }
    addr_list = (struct in_addr **)he->h_addr_list;
    strcpy(remote_host, inet_ntoa(*addr_list[0]));
    return 0;
}

int findlocalip(char *ip)
{
    struct ifaddrs *ifaddr, *ifa;
    char ip_str[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) < 0)
    {
        plog(LOG_CRIT, "getifaddrs is fail\n");
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
        {
            continue;
        }
        switch (ifa->ifa_addr->sa_family)
        {
        case AF_INET:
        {
            struct sockaddr_in *a = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &(a->sin_addr), ip_str, INET_ADDRSTRLEN);
            uint32_t n = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
            int i = 0;
            while (n > 0)
            {
                if (n & 1)
                    i++;
                n = n >> 1;
            }
            if (strcmp(ip, ip_str) == 0)
                return 0;
            // log("%s: %s/%d\n", ifa->ifa_name, ip_str, i);
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &(a->sin6_addr), ip_str, INET6_ADDRSTRLEN);
            unsigned char *c = ((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr.s6_addr;
            int i = 0, j = 0;
            unsigned char n = 0;
            while (i < 16)
            {
                n = c[i];
                while (n > 0)
                {
                    if (n & 1)
                        j++;
                    n = n / 2;
                }
                i++;
            }
            if (strcmp(ip, ip_str) == 0)
                return 0;
            // log("%s: %s/%d\n", ifa->ifa_name, ip_str, j);
            break;
        }
        default:
            break;
        }
    }
    freeifaddrs(ifaddr);
    return -1;
}

char *trimwhitespace(char *str)
{
    char *end;
    while (isspace((unsigned char)*str))
        str++;
    if (*str == 0) // All spaces?
        return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;
    *(end + 1) = 0;
    return str;
}
int acl(const char *path, struct domainlist *domainline)
{
    struct domainlist *tmp;
    INIT_LIST_HEAD(&(domainline->list));
    if (path == NULL)
    {
        return -1;
    }
    FILE *f = fopen(path, "r");
    if (f == NULL)
    {
        return -1;
    }
    char *buf = NULL;
    if (!(buf = malloc(500)))
    {
        fprintf(stderr, "No memory for configuration");
        return -1;
    }
    while (!feof(f))
        if (fgets((char *)buf, 256, f))
        {
            int long_line = 0; // 1: Long  2: Error
            while ((strlen(buf) == 255) && (buf[254] != '\n'))
            {
                long_line = 1;
                if (fgets((char *)buf, 256, f) == NULL)
                {
                    long_line = 2;
                    break;
                }
            }
            if (long_line)
            {
                if (long_line == 1)
                {
                    plog(LOG_CRIT, "Discarding long ACL content: %s", buf);
                }
                continue;
            }
            // Trim the newline
            int len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n')
            {
                buf[len - 1] = '\0';
            }
            char *comment = strchr(buf, '#');
            if (comment)
            {
                *comment = '\0';
            }
            char *line = trimwhitespace(buf);
            if (strlen(line) == 0)
            {
                continue;
            }
            char *line_buf = (char *)malloc(strlen(line) + 1);
            strcpy(line_buf, line);
            // log("line_buf is %s\n",line_buf);
            tmp = (struct domainlist *)malloc(sizeof(struct domainlist));
            tmp->domain = line_buf;
            // tmp->domain = line;
            list_add(&(tmp->list), &(domainline->list));
        }
    tmp = (struct domainlist *)malloc(sizeof(struct domainlist));
    fclose(f);
    free(buf);
    buf = NULL;
    free(tmp);
    // free(tmp);
    return 0;
}

static int simplematch(const char *pattern, const char *text)
{
    const unsigned char *pat = (const unsigned char *)pattern;
    const unsigned char *txt = (const unsigned char *)text;
    const unsigned char *fallback = pat;
    int wildcard = 0;

    unsigned char lastchar = 'a';
    unsigned i;
    unsigned char charmap[32];

    while (*txt)
    {
        if (*pat == '\0')
        {
            if (wildcard)
            {
                pat = fallback;
            }
            else
            {
                return 1;
            }
        }
        if (*pat == '*')
        {
            if (*++pat == '\0')
            {
                return 0;
            }
            wildcard = 1;
            fallback = pat;
        }
        if (*pat == '[')
        {
            memset(charmap, '\0', sizeof(charmap));

            while (*++pat != ']')
            {
                if (!*pat)
                {
                    return 1;
                }
                else if (*pat == '-')
                {
                    if ((*++pat == ']') || *pat == '\0')
                    {
                        return (1);
                    }
                    for (i = lastchar; i <= *pat; i++)
                    {
                        charmap[i / 8] |= (unsigned char)(1 << (i % 8));
                    }
                }
                else
                {
                    charmap[*pat / 8] |= (unsigned char)(1 << (*pat % 8));
                    lastchar = *pat;
                }
            }
        }

        if ((*pat == *txt) || (*pat == '?') || ((*pat == ']') && (charmap[*txt / 8] & (1 << (*txt % 8)))))
        {
            pat++;
        }
        else if (!wildcard)
        {
            return 1;
        }
        else if (pat != fallback)
        {

            if (*pat == ']')
            {
                txt++;
            }
            pat = fallback;
            continue;
        }
        txt++;
    }
    if (*pat == '*')
        pat++;
    return (*pat);
}

int extract_https_header(unsigned char *bytes, size_t length, char **hostname)
{
    /* 1   TLS_HANDSHAKE_CONTENT_TYPE
     * 1   TLS major version
     * 1   TLS minor version
     * 2   TLS Record length
     * --------------
     * 1   Handshake type
     * 3   Length
     * 2   Version
     * 32  Random
     * 1   Session ID length
     * ?   Session ID
     * 2   Cipher Suites length
     * ?   Cipher Suites
     * 1   Compression Methods length
     * ?   Compression Methods
     * 2   Extensions length
     * ---------------
     * 2   Extension data length
     * 2   Extension type (0x0000 for server_name)
     * ---------------
     * 2   server_name list length
     * 1   server_name type (0)
     * 2   server_name length
     * ?   server_name
     */
    const int TLS_HEADER_LEN = 5;
    const int FIXED_LENGTH_RECORDS = 38;
    const int TLS_HANDSHAKE_CONTENT_TYPE = 0x16;
    const int TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;

    static char host[256];
    host[0] = '\0';

    int pos = 0;
    if (length < TLS_HEADER_LEN + FIXED_LENGTH_RECORDS)
    {
        // not enough data
        return -1;
    }

    if ((bytes[0] & 0x80) && (bytes[2] == 1))
    {
        // SSL 2.0, does not support SNI
        return -1;
    }
    if (bytes[0] != TLS_HANDSHAKE_CONTENT_TYPE)
    {
        return -1;
    }
    if (bytes[1] < 3)
    {
        // TLS major version < 3, does not support SNI
        return -1;
    }
    int record_len = (bytes[3] << 8) + bytes[4] + TLS_HEADER_LEN;
    if (length < record_len)
    {
        // not enough data
        return -1;
    }
    if (bytes[TLS_HEADER_LEN] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    {
        // invalid handshake type
        return -1;
    }
    pos += TLS_HEADER_LEN + FIXED_LENGTH_RECORDS;

    // skip session ID
    if (pos + 1 > length || pos + 1 + bytes[pos] > length)
    {
        // not enough data
        return -1;
    }
    pos += 1 + bytes[pos];
    // skip cipher suites
    if (pos + 2 > length || pos + 2 + (bytes[pos] << 8) + bytes[pos + 1] > length)
    {
        // not enough data
        return -1;
    }
    pos += 2 + (bytes[pos] << 8) + bytes[pos + 1];
    // skip compression methods
    if (pos + 1 > length || pos + 1 + bytes[pos] > length)
    {
        // not enough data
        return -1;
    }
    pos += 1 + bytes[pos];
    // skip extension length
    if (pos + 2 > length)
    {
        return -1;
    }
    pos += 2;

    // parse extension data
    while (1)
    {
        if (pos + 4 > record_len)
        {
            // buffer more than one record, SNI still not found
            return -1;
        }
        if (pos + 4 > length)
        {
            return -1;
        }
        int ext_data_len = (bytes[pos + 2] << 8) + bytes[pos + 3];
        if (bytes[pos] == 0 && bytes[pos + 1] == 0)
        {
            // server_name extension type
            pos += 4;
            if (pos + 5 > length)
            {
                // server_name list header
                return -1;
            }
            int server_name_len = (bytes[pos + 3] << 8) + bytes[pos + 4];
            if (pos + 5 + server_name_len > length)
            {
                return -1;
            }
            // return server_name
            if (server_name_len + 1 > (int)sizeof(host))
            {
                return -1;
            }
            memcpy(host, bytes + pos + 5, server_name_len);
            host[server_name_len] = '\0';
            *hostname = host;
            return 0;
        }
        else
        {
            // skip
            pos += 4 + ext_data_len;
        }
    }
}

int receive_data(int socket, char *buffer, int len)
{
    int n = recv(socket, buffer, len, 0);
    return n;
}

int read_header(int fd, char *buffer)
{
    memset(buffer, 0, BUF_SIZE);
    size_t total = 0, len = 100;
    char line_buffer[len];
    for (;;)
    {
        memset(line_buffer, 0, len);
        ssize_t numRead = recv(fd, line_buffer, len, MSG_DONTWAIT);
        //LOG("recv len is %ld\n", numRead);
        if (numRead > 0)
        {
            if (numRead < len)
            {
                memcpy(buffer, line_buffer, numRead);
                total = total + numRead;
                break;
            }
            memcpy(buffer, line_buffer, len);
            buffer += len;
            total = total + numRead;
        }
        else
        {
            if ((numRead < 0) && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            {
                if (total > 0)
                    break;
                continue;
            }
            else
            {
                return -1;
            }
        }
    }
    return total;
}

int send_data(int socket, char *buffer, int len)
{
    return send(socket, buffer, len, 0);
}

int create_connection()
{
    struct addrinfo hints, *res = NULL;
    int sock;
    int validfamily = 0;
    char portstr[12];
    int fwmark = 10;
    struct timeval tv_timeout;
    tv_timeout.tv_sec = 2;
    tv_timeout.tv_usec = 0;

    memset(&hints, 0x00, sizeof(hints));

    hints.ai_flags = AI_NUMERICSERV; /* numeric service number, not resolve */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    sprintf(portstr, "%d", remote_port);

    /* check for numeric IP to specify IPv6 or IPv4 socket */
    if (validfamily == check_ipversion(remote_host))
    {
        hints.ai_family = validfamily;
        hints.ai_flags |= AI_NUMERICHOST; /* remote_host is a valid numeric ip, skip resolve */
    }

    /* Check if specified host is valid. Try to resolve address if remote_host is a hostname */
    if (getaddrinfo(remote_host, portstr, &hints, &res) != 0)
    {
        errno = EFAULT;
        return -1;
    }

    if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
    {
        return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_MARK, &fwmark, sizeof fwmark) == -1)
    {
        plog(LOG_CRIT, "failed setting mark for socket packets");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (void *)&tv_timeout, sizeof(struct timeval)) == -1)
    {
        plog(LOG_CRIT, "failed setting timeout for socket packets");
    }
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0)
    {
        return -1;
    }

    if (res != NULL)
        freeaddrinfo(res);
    return sock;
}

void forward_data(int source_sock, int destination_sock)
{
    char buffer[BUF_SIZE];
    int n;
    while ((n = receive_data(source_sock, buffer, BUF_SIZE)) > 0)
    {

        send_data(destination_sock, buffer, n);
    }
    shutdown(destination_sock, SHUT_RDWR);
    shutdown(source_sock, SHUT_RDWR);
}

int parse_options(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, ":p:h:dsr:")) != -1)
    {
        switch (opt)
        {
        case 'p':
            bind_port = atoi(optarg);
            break;
        case 'h':
            bind_addr = optarg;
            break;
        case 's':
            use_syslog = TRUE;
            break;
        case 'd':
            foreground = TRUE;
            break;
        case 'r':
            blacklist_file = optarg;
            break;
        default:
            usage();
        }
    }
    return 0;
}
void sigterm_handler(int signal)
{
    close(client_sock);
    close(server_sock);
    exit(0);
}
void sigchld_handler(int signal)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
}
int check_ipversion(char *address)
{
    /* Check for valid IPv4 or Iv6 string. Returns AF_INET for IPv4, AF_INET6 for IPv6 */

    struct in6_addr bindaddr;

    if (inet_pton(AF_INET, address, &bindaddr) == 1)
    {
        return AF_INET;
    }
    else
    {
        if (inet_pton(AF_INET6, address, &bindaddr) == 1)
        {
            return AF_INET6;
        }
    }
    return 0;
}
int create_server_socket()
{

    int server_sock, optval = 1;
    int validfamily = 0;
    struct addrinfo hints, *res = NULL;
    char portstr[12];

    memset(&hints, 0x00, sizeof(hints));
    server_sock = -1;

    hints.ai_flags = AI_NUMERICSERV; /* numeric service number, not resolve */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* prepare to bind on specified numeric address */
    if (bind_addr != NULL)
    {
        /* check for numeric IP to specify IPv6 or IPv4 socket */
        if (validfamily == check_ipversion(bind_addr))
        {
            hints.ai_family = validfamily;
            hints.ai_flags |= AI_NUMERICHOST; /* bind_addr is a valid numeric ip, skip resolve */
        }
    }
    else
    {
        /* if bind_address is NULL, will bind to IPv6 wildcard */
        hints.ai_family = AF_INET6;   /* Specify IPv6 socket, also allow ipv4 clients */
        hints.ai_flags |= AI_PASSIVE; /* Wildcard address */
    }
    sprintf(portstr, "%d", bind_port);
    /* Check if specified socket is valid. Try to resolve address if bind_address is a hostname */
    if (getaddrinfo(bind_addr, portstr, &hints, &res) != 0)
    {
        return -1;
    }
    if ((server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
    {
        return -1;
    }
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        return -1;
    }
    if (bind(server_sock, res->ai_addr, res->ai_addrlen) == -1)
    {
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, BACKLOG) < 0)
    {
        return -1;
    }
    if (res != NULL)
        freeaddrinfo(res);

    return server_sock;
}

int extract_http_header(const char *header, char **hostname)
{
    static char _p[256];
    char *p = strstr(header, "Host:");
    if (!p)
    {
        return -1;
    }
    char *p1 = strchr(p, '\n');
    if (!p1)
    {
        return -1;
    }
    char *p2 = strchr(p + 5, ':'); /* 5是指'Host:'的长度 */
    if (p2 && p2 < p1)
    {
        int h_len = (int)(p2 - p - 5 - 1);
        strncpy(_p, p + 5 + 1, h_len);
    }
    else
    {
        int h_len = (int)(p1 - p - 5 - 1 - 1);
        strncpy(_p, p + 5 + 1, h_len);
    }
    *hostname = (char *)_p;
    return 0;
}

void server_loop()
{
    //   struct sockaddr_in client_addr;
    struct sockaddr_storage client_addr;
    socklen_t addrlen = sizeof(client_addr);

    while (1)
    {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addrlen);

        if (fork() == 0)
        { // 创建子进程处理客户端连接请求
            close(server_sock);
            handle_client(client_sock, client_addr);
            exit(0);
        }
        close(client_sock);
    }
}
int getremoteaddr(int sockt)
{
    int error = 0;
    struct sockaddr_storage destaddr;
    memset(&destaddr, 0, sizeof(struct sockaddr_storage));
    socklen_t destaddr_len = sizeof(destaddr);
    error = getsockopt(sockt, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr *)&destaddr, &destaddr_len);
    if (error)
    {
        error = getsockopt(sockt, SOL_IPV6, IP6T_SO_ORIGINAL_DST, (struct sockaddr *)&destaddr, &destaddr_len);
    }
    if (error)
    {
        plog(LOG_CRIT, "getsockopt V6 addr fail");
    }
    if (destaddr.ss_family == AF_INET)
    {
        struct sockaddr_in *sa = (struct sockaddr_in *)&(destaddr);
        inet_ntop(AF_INET, &(sa->sin_addr), remote_host, INET_ADDRSTRLEN);
        remote_port = ntohs(sa->sin_port);
    }
    else
    {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&(destaddr);
        inet_ntop(AF_INET6, &(sa->sin6_addr), remote_host, INET6_ADDRSTRLEN);
        remote_port = ntohs(sa->sin6_port);
    }
}

void handle_client(int client_sock, struct sockaddr_storage client_addr)
{
    int len = -1;
    char *server_name;
    bool localstat = FALSE;
    bool sslstat = FALSE;
    struct list_head *pos;
    struct domainlist *tmp;
    getremoteaddr(client_sock);
    if (findlocalip(remote_host) == 0)
    {
        localstat = TRUE;
        resolvstat = TRUE;
    }
    if (remote_port == 80 || remote_port == 443 || localstat == TRUE)
    {
        len = read_header(client_sock, header_buffer);
        if (len < 0)
        {
            plog(LOG_CRIT, "Read header failed");
            return;
        }
        if (extract_https_header((unsigned char *)header_buffer, len, &server_name) == 0)
        {
            sslstat = TRUE;
        }
        else
        {
            if (extract_http_header(header_buffer, &server_name) != 0)
            {
                server_name = NULL;
                close(client_sock);
                return;
            }
        }
        if (server_name != NULL)
        {
            if (blacklist_file_stat == TRUE)
            {
                list_for_each(pos, &(blacklist.list))
                {
                    tmp = list_entry(pos, struct domainlist, list);
                    if (simplematch(tmp->domain, server_name) == 0)
                    {
                        plog(LOG_CRIT, "servername is %s drop", server_name);
                        close(client_sock);
                        return;
                    }
                }
            }
            if (resolvstat == TRUE)
            {
                hostname_to_ip(server_name);
                if (sslstat == TRUE)
                {
                    remote_port = 443;
                }
                else
                {
                    remote_port = 80;
                }
            }
        }
        plog(LOG_CRIT, "servername is %s accept", server_name);
    }

    plog(LOG_CRIT, "connect to host [%s:%d]", remote_host, remote_port);
    if ((remote_sock = create_connection()) < 0)
    {
        close(remote_sock);
        close(client_sock);
        plog(LOG_CRIT, "Cannot connect to host [%s:%d]", remote_host, remote_port);
        return;
    }
    if (fork() == 0)
    {
        if (strlen(header_buffer) > 0)
        {
            send_data(remote_sock, header_buffer, len);
        }
        forward_data(client_sock, remote_sock);
        exit(0);
    }
    if (fork() == 0)
    {
        forward_data(remote_sock, client_sock);
        exit(0);
    }
    close(remote_sock);
    close(client_sock);
}

int main(int argc, char *argv[])
{
    pid_t pid;
    parse_options(argc, argv);
    header_buffer = (char *)malloc(BUF_SIZE);

    if (use_syslog)
        openlog("proxy", LOG_PID, LOG_DAEMON);
    if ((server_sock = create_server_socket(bind_addr, bind_port)) < 0)
    {
        plog(LOG_CRIT, "Cannot run server: %m");
        exit(server_sock);
    }
    signal(SIGCHLD, sigchld_handler);
    signal(SIGTERM, sigterm_handler);
    if (acl(blacklist_file, &blacklist) == 0)
    {
        blacklist_file_stat = TRUE;
    }
    if (foreground == FALSE)
    {
        server_loop();
    }
    else
    {
        switch (pid = fork())
        {
        case 0: // deamonized child
            server_loop();
            break;
        case -1: // error
            plog(LOG_CRIT, "Cannot daemonize: %m");
            return pid;
        default: // parent
            close(server_sock);
        }
    }
    if (use_syslog)
        closelog();
    return 0;
}
