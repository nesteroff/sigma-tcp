/**
 * Copyright (C) 2012 Analog Devices, Inc.
 *
 * THIS SOFTWARE IS PROVIDED BY ANALOG DEVICES "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, NON-INFRINGEMENT,
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *
 **/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdbool.h>

#include "sigma_tcp.h"

#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

#include <time.h>
#include <sys/time.h>
#include <stdarg.h>

#define LOG_PATH "/var/log/sigma_tcp"
//#define LOG_TO_FILE

void simple_log(const char *str, ...)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm *today = localtime(&tv.tv_sec);
    char time_buf[20] = {0};
    strftime(time_buf, sizeof(time_buf), "%d.%m.%Y %H:%M:%S", today);

    char ms_buf[20] = {0};
    sprintf(ms_buf, "%06ld", tv.tv_usec);

    va_list ap;
    va_start(ap, str);
    printf("%s.%s ", time_buf, ms_buf);
    vprintf(str, ap);
    printf("\n");
    va_end(ap);

#ifdef LOG_TO_FILE
    va_start(ap, str);
    FILE *fp = fopen(LOG_PATH, "a+");
    if (fp) {
        fprintf(fp, "%s.%s ", time_buf, ms_buf);
        vfprintf(fp, str, ap);
        fprintf(fp, "\n");
        fclose(fp);
    }
    va_end(ap);
#endif
}

char *to_hex(uint8_t *data, int len)
{
	static char hex[512];
	memset(hex, 0, sizeof(hex));

	if (len >= (sizeof(hex) / 2)) {
		sprintf(hex, "[%d bytes]", len);
		return hex;
	}

	for (int i = 0; i < len; ++i)
		sprintf(hex + i * 2, "%02X", data[i]);
	return hex;
}


static void addr_to_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	switch(sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
				s, maxlen);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
				s, maxlen);
		break;
	default:
		strncpy(s, "Unkown", maxlen);
		break;
	}
}

static int show_addrs(int sck)
{
	char buf[256];
	char ip[INET6_ADDRSTRLEN];
	struct ifconf ifc;
	struct ifreq *ifr;
	unsigned int i, n;
	int ret;

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	ret = ioctl(sck, SIOCGIFCONF, &ifc);
	if (ret < 0) {
		perror("ioctl(SIOCGIFCONF)");
		return 1;
	}

	ifr = ifc.ifc_req;
	n = ifc.ifc_len / sizeof(struct ifreq);

	printf("IP addresses:\n");

	for (i = 0; i < n; i++) {
		struct sockaddr *addr = &ifr[i].ifr_addr;

		if (strcmp(ifr[i].ifr_name, "lo") == 0)
			continue;

		addr_to_str(addr, ip, INET6_ADDRSTRLEN);
		printf("%s: %s\n", ifr[i].ifr_name, ip);
	}

	return 0;
}

#define COMMAND_READ 0x0a
#define COMMAND_READ_RESPONSE 0x0b
#define COMMAND_WRITE 0x09

static uint8_t debug_data[256];

static int debug_read(unsigned int addr, unsigned int len, uint8_t *data)
{
	if (addr < 0x4000 || addr + len > 0x4100) {
		memset(data, 0x00, len);
		return 0;
	}

	printf("read: %.2x %d\n", addr, len);

	addr -= 0x4000;
	memcpy(data, debug_data + addr, len);

	return 0;
}

static int debug_write(unsigned int addr, unsigned int len, const uint8_t *data)
{
	if (addr < 0x4000 || addr + len > 0x4100)
		return 0;

	printf("write: %.2x %d\n", addr, len);

	addr -= 0x4000;
	memcpy(debug_data + addr, data, len);

	return 0;
}

static const struct backend_ops debug_backend_ops = {
	.read = debug_read,
	.write = debug_write,
};

static const struct backend_ops *backend_ops = &debug_backend_ops;

static void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static void handle_connection(int fd)
{
	uint8_t *buf;
	size_t buf_size;
	uint8_t *p;
	unsigned int len;
	unsigned int addr;
	unsigned int total_len;
	int count, ret;
	char command;

	count = 0;

	buf_size = 256;
	buf = malloc(buf_size);
	if (!buf)
		goto exit;
	p = buf;

	while (1) {
		memmove(buf, p, count);

		if (buf_size <= count) {
			buf_size += 256;
			buf = realloc(buf, buf_size);
		}

		ret = read(fd, buf + count, buf_size - count);
		if (ret <= 0)
			break;
		simple_log("Recv %d bytes: %s", ret, to_hex(buf + count, ret));

		p = buf;
		count += ret;
		//simple_log("Buf (count %d): %s", count, to_hex(buf, count));

		// Message header is 8 bytes
		while (count >= 8) {
			command = p[0]; // read or write
			total_len = (p[1] << 8) | p[2]; // total message length
			len = (p[4] << 8) | p[5]; // how many bytes to read
			addr = (p[6] << 8) | p[7]; // address
			int chip_addr = p[3]; // probably chip address

			if (command == COMMAND_READ) {
				simple_log("Read command: 0x%02X, total_len: %d, chip_addr: 0x%02X, len: %d, addr: 0x%04X", command, total_len, chip_addr, len, addr);

				int response_len = 4 + len;
				uint8_t *response = malloc(response_len);

				// Read data
				int read_res = backend_ops->read(addr, len, response + 4);
				if (read_res < 0)
					simple_log("Failed to read: %d errno: %d", read_res, errno);
				//simple_log("Read result: %d data: %s", read_res, to_hex(response + 4, len));

				// Send response
				response[0] = COMMAND_READ_RESPONSE;
				response[1] = response_len >> 8;
				response[2] = response_len & 0xff;
				response[3] = read_res >= 0 ? 0 : 1; // Probably read result: 0 - success, 1 - failure
				write(fd, response, response_len);
				simple_log("Sent %02d bytes: %s", response_len, to_hex(response, response_len));
				free(response);

				// Move on to the next command
				p += 8;
				count -= 8;

			} else if (command == COMMAND_WRITE) {
				// Not enough data, fetch next bytes
				if (count < len + 8) {
					// Buffer is not large enough, reallocate
					if (buf_size < len + 8) {
						// Move unprocessed bytes to the front because the p pointer will no longer be valid after realloc
						memmove(buf, p, count);
						buf_size = len + 8;
						buf = realloc(buf, buf_size);
						p = buf;
						if (!buf)
							goto exit;
					}
					break;
				}

				simple_log("Write command: 0x%02X, total_len: %d, chip_addr: 0x%02X, len: %d, addr: 0x%04X, data: %s", command, total_len, chip_addr, len, addr, to_hex(p + 8, len));

				// Write data
				int write_res = backend_ops->write(addr, len, p + 8);
				if (write_res < 0)
					simple_log("Failed to write: %d errno: %d", write_res, errno);

				// Move on to the next command
				p += (len + 8);
				count -= (len + 8);
			}
			else if (command == 0x1B) {
				// This command is sent when the Register ASAP connection button is pressed in SigmaStudio
				simple_log("ASAP command: 0x%02X, total_len: %d, chip_addr: 0x%02X, len: %d, addr: 0x%04X, data: %s", command, total_len, chip_addr, len, addr, to_hex(p + 8, len));

				// Move on to the next command
				p += (len + 8);
				count -= (len + 8);
			}
			else {
				simple_log("Unknown command: 0x%02X!", command);
				//abort();

				// Move on to the next command
				p += (len + 8);
				count -= (len + 8);
			}
		}
	}

exit:
	free(buf);
}

int main(int argc, char *argv[])
{
    int sockfd, new_fd;
	struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    int reuse = 1;
    char s[INET6_ADDRSTRLEN];
    int ret;

	if (argc >= 2) {
		if (strcmp(argv[1], "debug") == 0)
			backend_ops = &debug_backend_ops;
		else if (strcmp(argv[1], "i2c") == 0)
			backend_ops = &i2c_backend_ops;
		else if (strcmp(argv[1], "regmap") == 0)
			backend_ops = &regmap_backend_ops;
		else {
			printf("Usage: %s <backend> <backend arg0> ...\n"
				   "Available backends: debug, i2c, regmap\n", argv[0]);
			exit(0);
		}

		printf("Using %s backend\n", argv[1]);
	}

	if (backend_ops->open) {
		ret = backend_ops->open(argc, argv);
		if (ret)
			exit(1);
	}

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(NULL, "8086", &hints, &servinfo);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "Failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfo);

    if (listen(sockfd, 0) == -1) {
        perror("listen");
        exit(1);
    }

    printf("Waiting for connections...\n");
	show_addrs(sockfd);

    while (true) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);

        simple_log("New connection from %s", s);
		handle_connection(new_fd);
        simple_log("Connection closed");
    }

    return 0;
}
