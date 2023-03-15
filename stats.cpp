/**
 * \file stats.cpp
 * \brief Implementation of service IO functions, modified code from libtrap service ifc and
 * trap_stats \author Jiri Havranek <havranek@cesnet.cz> \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include <config.h>
#include <string>

#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "stats.hpp"

namespace Ipxp {

int connectToExporter(const char* path)
{
	int fd;
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s", path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd != -1) {
		if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
			perror("unable to connect");
			close(fd);
			return -1;
		}
	}
	return fd;
}

int createStatsSock(const char* path)
{
	int fd;
	struct sockaddr_un addr;

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path) - 1, "%s", path);

	unlink(addr.sun_path);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd != -1) {
		if (bind(fd, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
			perror("unable to bind socket");
			close(fd);
			return -1;
		}
		if (listen(fd, 1) == -1) {
			perror("unable to listen on socket");
			close(fd);
			return -1;
		}
		if (chmod(addr.sun_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) == -1) {
			perror("unable to set access rights");
			close(fd);
			return -1;
		}
	}
	return fd;
}

int recvData(int fd, uint32_t size, void* data)
{
	size_t numOfTimeouts = 0;
	size_t totalReceived = 0;
	ssize_t lastReceived = 0;

	while (totalReceived < size) {
		lastReceived
			= recv(fd, (uint8_t*) data + totalReceived, size - totalReceived, MSG_DONTWAIT);
		if (lastReceived == 0) {
			return -1;
		} else if (lastReceived == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				numOfTimeouts++;
				if (numOfTimeouts > SERVICE_WAIT_MAX_TRY) {
					return -1;
				} else {
					usleep(SERVICE_WAIT_BEFORE_TIMEOUT);
					continue;
				}
			}
			return -1;
		}
		totalReceived += lastReceived;
	}
	return 0;
}

int sendData(int fd, uint32_t size, void* data)
{
	size_t numOfTimeouts = 0;
	size_t totalSent = 0;
	ssize_t lastSent = 0;

	while (totalSent < size) {
		lastSent = send(fd, (uint8_t*) data + totalSent, size - totalSent, MSG_DONTWAIT);
		if (lastSent == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				numOfTimeouts++;
				if (numOfTimeouts > SERVICE_WAIT_MAX_TRY) {
					return -1;
				} else {
					usleep(SERVICE_WAIT_BEFORE_TIMEOUT);
					continue;
				}
			}
			return -1;
		}
		totalSent += lastSent;
	}
	return 0;
}

std::string createSockpath(const char* id)
{
	return DEFAULTSOCKETDIR "/ipfixprobe_" + std::string(id) + ".sock";
}

} // namespace ipxp
