#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	char *arguments, *pos;
	int i, writefd, len = 0;

	if ((writefd = open(EBTD_PIPE, O_WRONLY, 0)) == -1) {
		perror("open");
		return -1;
	}

	if (argc > EBTD_ARGC_MAX) {
		printf("ebtablesd accepts at most %d arguments, %d arguments "
		       "were specified. If you need this many arguments, "
		       "recompile this tool with a higher value for "
		       "EBTD_ARGC_MAX.\n", EBTD_ARGC_MAX - 1, argc - 1);
		return -1;
	} else if (argc == 1) {
		printf("At least one argument is needed.\n");
		return -1;
	}

	for (i = 0; i < argc; i++)
		len += strlen(argv[i]);
	/* Don't forget '\0' */
	len += argc;
	if (len > EBTD_CMDLINE_MAXLN) {
		printf("ebtablesd has a maximum command line argument length "
		       "of %d, an argument length of %d was received. If a "
		       "smaller length is unfeasible, recompile this tool "
		       "with a higher value for EBTD_CMDLINE_MAXLN.\n",
		       EBTD_CMDLINE_MAXLN, len);
		return -1;
	}

	if (!(arguments = (char *)malloc(len))) {
		printf("ebtablesu: out of memory.\n");
		return -1;
	}

	pos = arguments;
	for (i = 0; i < argc; i++) {
		strcpy(pos, argv[i]);
		pos += strlen(argv[i]) + 1;
	}

	*(pos-1) = '\n';
	if (write(writefd, arguments, len) == -1) {
		perror("write");
		return -1;
	}
	return 0;
}
