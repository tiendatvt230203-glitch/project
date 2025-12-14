/*
 * Point-to-Point Tunnel Daemon
 *
 * Usage: tunnel -c <config_file> [-d]
 *   -c  Config file path
 *   -d  Run as daemon (background)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

#include "tunnel.h"

static tunnel_t tunnel;

static void signal_handler(int sig) {
    (void)sig;
    tunnel_stop(&tunnel);
}

static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    if (setsid() < 0) exit(1);

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    umask(0);
    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}

int main(int argc, char *argv[]) {
    const char *config = NULL;
    int daemon_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0) {
            daemon_mode = 1;
        }
    }

    if (!config) {
        fprintf(stderr, "Usage: %s -c <config_file> [-d]\n", argv[0]);
        return 1;
    }

    if (tunnel_init(&tunnel, config) < 0) {
        fprintf(stderr, "Failed to initialize tunnel\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (daemon_mode) {
        daemonize();
        openlog("tunnel", LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Tunnel daemon started");
    }

    tunnel_run(&tunnel);

    tunnel_cleanup(&tunnel);

    if (daemon_mode) {
        syslog(LOG_INFO, "Tunnel daemon stopped");
        closelog();
    }

    return 0;
}
