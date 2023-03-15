/**
 * \file stats.hpp
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
#ifndef IPXP_PROCESS_STATS_HPP
#define IPXP_PROCESS_STATS_HPP

#include <ostream>

#include <ipfixprobe/options.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/utils.hpp>

namespace Ipxp {

#define STATS_PRINT_INTERVAL 1

class StatsOptParser : public OptionsParser {
public:
	uint32_t mInterval;
	std::string mOut;

	StatsOptParser()
		: OptionsParser("stats", "Print storage plugin statistics")
		, mInterval(STATS_PRINT_INTERVAL)
		, mOut("stdout")
	{
		registerOption(
			"i",
			"interval",
			"SECS",
			"Print interval in seconds",
			[this](const char* arg) {
				try {
					mInterval = str2num<decltype(mInterval)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"o",
			"out",
			"DESC",
			"Print statistics to stdout or stderr",
			[this](const char* arg) {
				mOut = arg;
				return mOut != "stdout" && mOut != "stderr";
			},
			OptionFlags::REQUIRED_ARGUMENT);
	}
};

class StatsPlugin : public ProcessPlugin {
public:
	StatsPlugin();
	~StatsPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new StatsOptParser(); }
	std::string getName() const { return "stats"; }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);
	void preExport(Flow& rec);
	void finish(bool printStats);

private:
	uint64_t m_packets;
	uint64_t m_new_flows;
	uint64_t m_cache_hits;
	uint64_t m_flows_in_cache;

	bool m_init_ts;
	struct timeval m_interval;
	struct timeval m_last_ts;
	std::ostream* m_out;

	void checkTimestamp(const Packet& pkt);
	void printHeader() const;
	void printLine(const struct timeval& ts) const;
};

} // namespace ipxp
#endif /* IPXP_PROCESS_STATS_HPP */
