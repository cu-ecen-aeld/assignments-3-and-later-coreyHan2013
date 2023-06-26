#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>

int main(int argc, char **argv)
{
	int fd;
	int count;
	ssize_t nr;

	openlog(NULL, 0, LOG_USER);
	if (argc < 3) {
		syslog(LOG_ERR, "Invalid number of arguments: %d", argc);
		printf("error:\n");
		if (argc == 1) 
			printf("    missing the first parameter: writefile\n");
		printf("    missing the second parameter: writestr\n");
		exit(1);
	}

	syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);

	fd = open(argv[1], O_WRONLY | O_CREAT, S_IRWXU | S_IRWXG | S_IROTH);
	if (fd == -1) {
		syslog(LOG_ERR, "Open file error: %s", strerror(errno));
		printf("Open file errno: %d, meaning: %s\n", errno, strerror(errno));
		exit(1);
	}

	count = strlen(argv[2]);
	nr = write(fd, argv[2], count);
	if (nr == -1) {
		syslog(LOG_ERR, "Write file error: %s", strerror(errno));
		printf("Write file errno: %d, meaning: %s\n", errno, strerror(errno));
		close(fd);
		exit(1);
	}
	else if (nr != count) {
		syslog(LOG_ERR, "Only %ld out of %d part of string has been written to the file", nr, count);
		printf("error: Not the whole string has been written to the file!\n");
		close(fd);
		exit(1);
	}

	close(fd);
	syslog(LOG_DEBUG, "successfully wrote the string");
	closelog();
	printf("successfully wrote the string\n");
}
