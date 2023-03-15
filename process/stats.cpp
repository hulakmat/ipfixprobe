/**
 * \file stats.cpp
 * \brief Plugin periodically printing statistics about flow cache
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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
#include "stats.hpp"

#include <iomanip>
#include <iostream>
#include <sys/time.h>

namespace Ipxp {

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("stats", []() { return new StatsPlugin(); });
	registerPlugin(&rec);
}

StatsPlugin::StatsPlugin()
	: m_packets(0)
	, m_new_flows(0)
	, m_cache_hits(0)
	, m_flows_in_cache(0)
	, m_init_ts(true)
	, m_interval({STATS_PRINT_INTERVAL, 0})
	, m_last_ts({0})
	, m_out(&std::cout)
{
}

StatsPlugin::~StatsPlugin()
{
	close();
}

void StatsPlugin::init(const char* params)
{
	StatsOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	m_interval = {parser.mInterval, 0};
	if (parser.mOut == "stdout") {
		m_out = &std::cout;
	} else if (parser.mOut == "stderr") {
		m_out = &std::cerr;
	} else {
		throw PluginError("Unknown argument " + parser.mOut);
	}
	printHeader();
}

void StatsPlugin::close() {}

ProcessPlugin* StatsPlugin::copy()
{
	return new StatsPlugin(*this);
}

int StatsPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	m_packets += 1;
	m_new_flows += 1;
	m_flows_in_cache += 1;
	checkTimestamp(pkt);
	return 0;
}

int StatsPlugin::postUpdate(Flow& rec, const Packet& pkt)
{
	m_packets += 1;
	m_cache_hits += 1;
	checkTimestamp(pkt);
	return 0;
}

void StatsPlugin::preExport(Flow& rec)
{
	m_flows_in_cache -= 1;
}

void StatsPlugin::finish(bool printStats)
{
	printLine(m_last_ts);
}

void StatsPlugin::checkTimestamp(const Packet& pkt)
{
	if (m_init_ts) {
		m_init_ts = false;
		m_last_ts = pkt.ts;
		return;
	}

	struct timeval tmp;
	timeradd(&m_last_ts, &m_interval, &tmp);

	if (timercmp(&pkt.ts, &tmp, >)) {
		printLine(m_last_ts);
		timeradd(&m_last_ts, &m_interval, &m_last_ts);
		m_packets = 0;
		m_new_flows = 0;
		m_cache_hits = 0;
	}
}

void StatsPlugin::printHeader() const
{
	*m_out << "#timestamp packets hits newflows incache" << std::endl;
}

void StatsPlugin::printLine(const struct timeval& ts) const
{
	*m_out << ts.tv_sec << "." << ts.tv_usec << " ";
	*m_out << m_packets << " " << m_cache_hits << " " << m_new_flows << " " << m_flows_in_cache
		   << std::endl;
}

} // namespace ipxp
