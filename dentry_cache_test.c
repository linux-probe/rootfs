#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	int fd = -1;
	char *file = NULL;
	if (argc != 2){
		printf("invalid param"
			"	eg:./dentry_cache_test rootfs_test\n"
		);
		return -1;
	}

	printf("first open %s\n", argv[1]);
	fd = open("/study/rootfs_study",O_RDONLY);
	if (fd < 0){
		perror("open failed\n");
		return -1;
	}

	close(fd);
	fd = -1;
	printf("second open %s\n", argv[1]);
	fd = open(argv[1],O_RDONLY);
	
	fd = open("/study/rootfs_study",O_RDONLY);
	if (fd < 0){
		perror("open failed\n");
		return -1;
	}
	close(fd);
	return 0;
}
