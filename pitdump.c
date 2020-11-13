#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <linux/fs.h>
#include <dirent.h>

struct __attribute__((packed)) pit {
	uint32_t magic;
	uint32_t entry_count;
	uint32_t port;
	uint32_t format;
	char chip[8];
	uint32_t unknown;

	struct __attribute__((packed)) pit_partition {
		uint32_t binary_type;
		uint32_t device_type;

		uint32_t identifier;

		uint32_t attributes;
		uint32_t update_attributes;

		uint32_t block_size_or_offset;
		uint32_t block_count;

		uint32_t file_offset;
		uint32_t file_size;

		char partition_name[32];
		char flash_filename[32];
		char fota_filename[32];
	} partition[];
};

typedef struct pit_partition pit_partition_t;
typedef struct pit pit_t;

#define MAGIC_PIT ((uint32_t)0x12349876)
#define PIT_HEADER_SIZE (sizeof(pit_t))
#define PIT_ENTRY_SIZE (sizeof(pit_partition_t))


static bool stop_on(bool print_errno, bool cond, const char *message, ...)
{
	if (!cond)
		return false;

	va_list args;
	va_start(args, message);
	vfprintf(stderr, message, args);
	va_end(args);
	if (print_errno)
		fprintf(stderr, ": %s", strerror(errno));
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);

	return true;
}

#define stopx(cond, ...) stop_on(false, cond, __VA_ARGS__)
#define stop(cond, ...) stop_on(true, cond, __VA_ARGS__)

static bool check_cond(bool print_errno, bool cond, const char *message, ...)
{
	if (!cond)
		return false;

	va_list args;
	va_start(args, message);
	vfprintf(stderr, message, args);
	va_end(args);
	if (print_errno)
		fprintf(stderr, ": %s", strerror(errno));
	fprintf(stderr, "\n");

	return true;
}

#define checkx(cond, ...) check_cond(false, cond, __VA_ARGS__)
#define check(cond, ...) check_cond(true, cond, __VA_ARGS__)

static inline size_t pit_size(uint32_t entry_count)
{
	return PIT_HEADER_SIZE + (entry_count * PIT_ENTRY_SIZE);
}

void dump_pit(int fd, off_t offset, const char *output)
{
	ssize_t res;
	uint8_t *addr;
	uint32_t entry_count;
	size_t size;

	res = pread(fd, &entry_count, sizeof(entry_count),
		    offset + sizeof(MAGIC_PIT));
	stop(res < 0, "can't read");
	stopx(res != sizeof(entry_count), "can't read entry_count");

	size = pit_size(entry_count);

	addr = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset);
	stop(addr == MAP_FAILED, "mmap failed");

	printf("writing PIT to %s\n", output);
	int outfd = creat(output, 0444);
	stop(outfd < 0, "can't create file %s", output);
	res = write(outfd, addr, size);
	check(res < 0, "can't write to %s", output);
	checkx((size_t)res < size, "can't dump full PIT (%zd/%zd)", res, size);
	munmap(addr, size);
}

static int check_device(const char *dev,
			unsigned check_blocks,
			off_t *offset)
{
	int fd;
	unsigned i;
	size_t block_size = 4096;

	fd = open(dev, O_RDONLY);
	if (check(fd < 0, "failed to open %s", dev))
		return -1;

	stop(ioctl(fd, BLKBSZGET, &block_size) < 0,
	     "%s can't determine block size", dev);

	for (i = 0; i < check_blocks; ++i) {
		uint32_t magic;
		off_t o = block_size * (off_t)i;

		ssize_t res = pread(fd, &magic, sizeof(magic), o);
		if (check(res < 0, "can't read from %s", dev) ||
		    checkx((size_t)res < sizeof(magic),
			   "can't read magic number")
		)
			break;

		if (magic == MAGIC_PIT) {
			*offset = o;
			return fd;
		}
	}

	close(fd);

	return -1;
}

#define CHECK_BLOCKS 10

#ifdef DYNAMIC
static inline bool starts_with(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

#define BLOCK "/dev/block"
static int check_all_block_devices(off_t *offset)
{
	DIR *d;
	struct dirent *dir;
	char block_path[sizeof(BLOCK) + NAME_MAX + 2];
	int fd = -1;

	d = opendir(BLOCK);
	stop(!d, "failed to open " BLOCK);

	while ((dir = readdir(d)) != NULL) {
		if (!starts_with(dir->d_name, "sd") || strlen(dir->d_name) != 3)
			continue;

		sprintf(block_path, "%s/%s", BLOCK, dir->d_name);

		printf("checking device %s...\n", block_path);

		fd = check_device(block_path, CHECK_BLOCKS, offset);
		if (fd < 0)
			continue;

		break;
	}

	closedir(d);

	return fd;
}
#else
static int check_all_block_devices(off_t *offset)
{
	int fd = -1;
	const char *devices[] = {
		"/dev/block/sda",
		"/dev/block/sdb",
		"/dev/block/sdc",
		"/dev/block/sdd",
		"/dev/block/sde",
		"/dev/sda",
		"/dev/sdb",
		"/dev/sdc",
		"/dev/sdd",
		"/dev/sde",
		NULL
	};
	const char **block_path = devices;

	do {
		if (access(*block_path, F_OK))
			continue;

		printf("checking device %s...\n", *block_path);

		fd = check_device(*block_path, CHECK_BLOCKS, offset);
		if (fd < 0)
			continue;

		break;
	} while (*(++block_path));

	return fd;
}
#endif

int main(int argc, char *argv[])
{
	int fd;
	off_t offset;
	const char *filename = "pit";

	if (argc > 2) {
		printf("Usage: %s <dump_to_file (\"pit\" by default)>\n", argv[0]);
		return 0;
	} else if (argc == 2) {
		filename = argv[1];
	}
	fd = check_all_block_devices(&offset);
	stopx(fd < 0, "can't find block device with PIT");

	dump_pit(fd, offset, filename);

	return EXIT_SUCCESS;
}
