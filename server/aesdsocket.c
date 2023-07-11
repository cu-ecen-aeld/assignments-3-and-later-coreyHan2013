#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <stdbool.h>
#include <signal.h>
#include <arpa/inet.h>

#define PORT 9000
#define BUF_SIZE 65535

#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("socket: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("socket ERROR: " msg "\n" , ##__VA_ARGS__)

const char *tmp_file = "/var/tmp/aesdsocketdata";
volatile bool caught_sig = false;

static void signal_handler(int signal_number)
{
    if (signal_number == SIGTERM || signal_number == SIGINT)
        caught_sig = true;
}

static void set_signal_handler()
{
    struct sigaction new_action;

    memset(&new_action, 0, sizeof(struct sigaction));
    new_action.sa_handler = signal_handler;
    if (sigaction(SIGTERM, &new_action, NULL) != 0) {
        ERROR_LOG("Error %d (%s) registering for SIGTERM", errno, strerror(errno));
        syslog(LOG_ERR, "Error %d (%s) registering for SIGTERM", errno, strerror(errno));
        exit(-1);
    }
    if (sigaction(SIGINT, &new_action, NULL) != 0) {
        ERROR_LOG("Error %d (%s) registering for SIGINT", errno, strerror(errno));
        syslog(LOG_ERR, "Error %d (%s) registering for SIGINT", errno, strerror(errno));
        exit(-1);
    }
}

static void socket_service(int server_fd)
{
    char *buffer;
    int new_socket, fd;
    struct sockaddr address;
    ssize_t recv_len, read_len;
    int addrlen = 0;
    char ipstr[INET6_ADDRSTRLEN];

    fd = open(tmp_file, O_RDWR | O_CREAT | O_TRUNC, 0664);
    if (fd == -1) {
        syslog(LOG_ERR, "Open file error: %s", strerror(errno));
        ERROR_LOG("Open file errno: %d, meaning: %s", errno, strerror(errno));
        exit(-1);
    }

    buffer = (char *)malloc(BUF_SIZE);
    memset(buffer, 0, BUF_SIZE);

    DEBUG_LOG("server is listening at port: %d", PORT);
    while (!caught_sig) {
        memset(&address, 0, sizeof(struct sockaddr));
        if ((new_socket
             = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen))
            < 0) {
            if (caught_sig)
                break;
            syslog(LOG_ERR, "accept failed");
            ERROR_LOG("Error %d (%s) accept", errno, strerror(errno));
            exit(-1);
        }
        if (address.sa_family == AF_INET6) { // AF_INET6
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&address;
            inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
        } else {
            struct sockaddr_in *s = (struct sockaddr_in *)&address;
            inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
        }

        syslog(LOG_DEBUG, "Accepted connection from %s", ipstr);
        DEBUG_LOG("Accepted connection from %s", ipstr);
        ssize_t start = 0;
        do {
            start += recv(new_socket, &buffer[start], BUF_SIZE, 0);
        } while (buffer[start-1] != '\n');
        recv_len = start;

        DEBUG_LOG("len=%ld, packet=%s", recv_len, buffer);
        lseek(fd, 0, SEEK_END);
        write(fd, buffer, recv_len);
        memset(buffer, 0, recv_len);

        lseek(fd, 0, SEEK_SET);
        start = 0;
        while (true) {
            while (true) {
                read_len = read(fd, &buffer[start], 1);
                if (buffer[start] == '\n' || read_len <= 0)
                    break;
                start++;
            }
            if (buffer[start] == '\n') {
                read_len = start + 1;
                DEBUG_LOG("read length is %ld, contents: %s", read_len, buffer);
                ssize_t send_len = send(new_socket, buffer, read_len, 0);
                memset(buffer, 0, send_len);
                start = 0;
            } else
                break;
        }
        close(new_socket);
        syslog(LOG_DEBUG, "Closed connection from %s", ipstr);
        DEBUG_LOG("Closed connection from %s", ipstr);
    }

    free(buffer);
    close(fd);
    remove(tmp_file);
}

int main(int argc, char **argv)
{
    int server_fd;
    pid_t pid;
    int i;
    struct sockaddr_in address;
    int opt = 1;

    openlog(NULL, 0, LOG_USER);

    server_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        syslog(LOG_ERR, "Invalid number of arguments: %d", server_fd);
        exit(-1);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        syslog(LOG_ERR, "setsockopt failed");
        exit(-1);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        syslog(LOG_ERR, "bind failed");
        exit(-1);
    }

    if ((argc > 1) && (strcmp(argv[1], "-d") == 0)) {
        DEBUG_LOG("Server will be put on daemon");
        pid = fork ();
        if (pid == -1)
            return -1;
        else if (pid != 0) {
            DEBUG_LOG("parent exits");
            syslog(LOG_DEBUG, "parent exits");
            closelog();
            exit(EXIT_SUCCESS);
        }

        /* create new session and process group */
        if (setsid () == -1)
            return -1;
        /* set the working directory to the root directory */
        if (chdir ("/") == -1)
            return -1;
        /* close all fid 0, 1, 2 */
        for (i = 0; i < 3; i++)
            close(i);
        /* redirect fd's 0,1,2 to /dev/null */
        open("/dev/null", O_RDWR);
        /* stdin */
        dup(0);
        /* stdout */
        dup(0);
        /* stderror */
    }

    if (listen(server_fd, 3) < 0) {
        syslog(LOG_ERR, "listen failed");
        exit(-1);
    }

    set_signal_handler();

    socket_service(server_fd);

    syslog(LOG_DEBUG, "Caught signal, exiting");
    shutdown(server_fd, SHUT_RDWR);
    syslog(LOG_DEBUG, "Successfully cleaned up");
    closelog();
    DEBUG_LOG("Successfully cleaned up");
    return 0;
}
