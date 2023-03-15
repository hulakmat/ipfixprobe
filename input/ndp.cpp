/**
 * \file ndp.cpp
 * \brief Packet reader using NDP library for high speed capture.
 * \author Tomas Benes <benesto@fit.cvut.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2020-2021 CESNET
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

#include <cstdio>
#include <cstring>
#include <iostream>

#include "ndp.hpp"
#include "parser.hpp"

namespace Ipxp {

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("ndp", []() { return new NdpPacketReader(); });
	registerPlugin(&rec);
}

void packetNdpHandler(
	parser_opt_t* opt,
	const struct ndp_packet* ndpPacket,
	const struct NdpHeader* ndpHeader)
{
	struct timeval ts;
	ts.tv_sec = le32toh(ndpHeader->timestampSec);
	ts.tv_usec = le32toh(ndpHeader->timestampNsec) / 1000;

	parsePacket(opt, ts, ndpPacket->data, ndpPacket->data_length, ndpPacket->data_length);
}

NdpPacketReader::NdpPacketReader() {}

NdpPacketReader::~NdpPacketReader()
{
	close();
}

void NdpPacketReader::init(const char* params)
{
	NdpOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	if (parser.mDev.empty()) {
		throw PluginError("specify device path");
	}
	initIfc(parser.mDev);
}

void NdpPacketReader::close()
{
	m_ndpReader.close();
}

void NdpPacketReader::initIfc(const std::string& dev)
{
	if (m_ndpReader.initInterface(dev) != 0) {
		throw PluginError(m_ndpReader.errorMsg);
	}
}

InputPlugin::Result NdpPacketReader::get(PacketBlock& packets)
{
	parser_opt_t opt = {&packets, false, false, 0};
	struct ndp_packet* ndpPacket;
	struct NdpHeader* ndpHeader;
	size_t readPkts = 0;
	int ret = -1;

	packets.cnt = 0;
	for (unsigned i = 0; i < packets.size; i++) {
		ret = m_ndpReader.getPkt(&ndpPacket, &ndpHeader);
		if (ret == 0) {
			if (opt.pblock->cnt) {
				break;
			}
			return Result::TIMEOUT;
		} else if (ret < 0) {
			// Error occured.
			throw PluginError(m_ndpReader.errorMsg);
		}
		readPkts++;
		packetNdpHandler(&opt, ndpPacket, ndpHeader);
	}

	mSeen += readPkts;
	mParsed += opt.pblock->cnt;
	return opt.pblock->cnt ? Result::PARSED : Result::NOT_PARSED;
}

} // namespace ipxp
