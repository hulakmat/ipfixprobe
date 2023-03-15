/**
 * \file text.cpp
 * \brief Prints exported fields
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
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

#include <fstream>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <string>

#include "text.hpp"

namespace Ipxp {

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("text", []() { return new TextExporter(); });
	registerPlugin(&rec);
}

TextExporter::TextExporter()
	: m_out(&std::cout)
	, m_hide_mac(false)
{
}

TextExporter::~TextExporter()
{
	close();
}

void TextExporter::init(const char* params)
{
	TextOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	if (parser.mToFile) {
		std::ofstream* file = new std::ofstream(parser.mFile, std::ofstream::out);
		if (file->fail()) {
			throw PluginError("failed to open output file");
		}
		m_out = file;
	}
	m_hide_mac = parser.mHideMac;

	if (!m_hide_mac) {
		*m_out << "mac ";
	}
	*m_out << "conversation packets bytes tcp-flags time extensions" << std::endl;
}

void TextExporter::init(const char* params, Plugins& plugins)
{
	init(params);
}

void TextExporter::close()
{
	if (m_out != &std::cout) {
		delete m_out;
		m_out = &std::cout;
	}
}

int TextExporter::exportFlow(const Flow& flow)
{
	RecordExt* ext = flow.mExts;

	mFlowsSeen++;
	printBasicFlow(flow);
	while (ext != nullptr) {
		*m_out << " " << ext->getText();
		ext = ext->mNext;
	}
	*m_out << std::endl;

	return 0;
}

void TextExporter::printBasicFlow(const Flow& flow)
{
	time_t sec;
	char timeBegin[100];
	char timeEnd[100];
	char srcMac[18];
	char dstMac[18];
	char tmp[50];
	char srcIp[INET6_ADDRSTRLEN];
	char dstIp[INET6_ADDRSTRLEN];
	std::string lb = "";
	std::string rb = "";

	sec = flow.timeFirst.tv_sec;
	strftime(tmp, sizeof(tmp), "%FT%T", localtime(&sec));
	snprintf(timeBegin, sizeof(timeBegin), "%s.%06ld", tmp, flow.timeFirst.tv_usec);
	sec = flow.timeLast.tv_sec;
	strftime(tmp, sizeof(tmp), "%FT%T", localtime(&sec));
	snprintf(timeEnd, sizeof(timeEnd), "%s.%06ld", tmp, flow.timeLast.tv_usec);

	const uint8_t* p = const_cast<uint8_t*>(flow.srcMac);
	snprintf(
		srcMac,
		sizeof(srcMac),
		"%02x:%02x:%02x:%02x:%02x:%02x",
		p[0],
		p[1],
		p[2],
		p[3],
		p[4],
		p[5]);
	p = const_cast<uint8_t*>(flow.dstMac);
	snprintf(
		dstMac,
		sizeof(dstMac),
		"%02x:%02x:%02x:%02x:%02x:%02x",
		p[0],
		p[1],
		p[2],
		p[3],
		p[4],
		p[5]);

	if (flow.ipVersion == IP::V4) {
		inet_ntop(AF_INET, (const void*) &flow.srcIp.v4, srcIp, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, (const void*) &flow.dstIp.v4, dstIp, INET6_ADDRSTRLEN);
	} else if (flow.ipVersion == IP::V6) {
		inet_ntop(AF_INET6, (const void*) &flow.srcIp.v6, srcIp, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (const void*) &flow.dstIp.v6, dstIp, INET6_ADDRSTRLEN);
		lb = "[";
		rb = "]";
	}

	if (!m_hide_mac) {
		*m_out << srcMac << "->" << dstMac << " ";
	}
	*m_out << std::setw(2) << static_cast<unsigned>(flow.ipProto) << "@" << lb << srcIp << rb
		   << ":" << flow.srcPort << "->" << lb << dstIp << rb << ":" << flow.dstPort << " "
		   << flow.srcPackets << "->" << flow.dstPackets << " " << flow.srcBytes << "->"
		   << flow.dstBytes << " " << static_cast<unsigned>(flow.srcTcpFlags) << "->"
		   << static_cast<unsigned>(flow.dstTcpFlags) << " " << timeBegin << "->" << timeEnd;
}

} // namespace ipxp
