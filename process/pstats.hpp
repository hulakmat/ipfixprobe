/**
 * \file pstats.h
 * \brief Plugin for parsing pstats traffic.
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Karel Hynek <hynekkar@cesnet.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
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
 * This software is provided as is'', and any express or implied
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

#ifndef IPXP_PROCESS_PSTATS_HPP
#define IPXP_PROCESS_PSTATS_HPP

#include <cstring>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

#include <ipfixprobe/byte-utils.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>

namespace Ipxp {

#ifndef PSTATS_MAXELEMCOUNT
#define PSTATS_MAXELEMCOUNT 30
#endif

#ifndef PSTATS_MINLEN
#define PSTATS_MINLEN 1
#endif

#define PSTATS_UNIREC_TEMPLATE "PPI_PKT_LENGTHS,PPI_PKT_TIMES,PPI_PKT_FLAGS,PPI_PKT_DIRECTIONS"

UR_FIELDS(
	uint16* PPI_PKT_LENGTHS,
	time* PPI_PKT_TIMES,
	uint8* PPI_PKT_FLAGS,
	int8* PPI_PKT_DIRECTIONS)

class PSTATSOptParser : public OptionsParser {
public:
	bool mIncludeZeroes;
	bool mSkipdup;

	PSTATSOptParser()
		: OptionsParser("pstats", "Processing plugin for packet stats")
		, mIncludeZeroes(false)
		, mSkipdup(false)
	{
		registerOption(
			"i",
			"includezeroes",
			"",
			"Include zero payload packets",
			[this](const char* arg) {
				mIncludeZeroes = true;
				return true;
			},
			OptionFlags::NO_ARGUMENT);
		registerOption(
			"s",
			"skipdup",
			"",
			"Skip duplicated TCP packets",
			[this](const char* arg) {
				mSkipdup = true;
				return true;
			},
			OptionFlags::NO_ARGUMENT);
	}
};

/**
 * \brief Flow record extension header for storing parsed PSTATS packets.
 */
struct RecordExtPSTATS : public RecordExt {
	static int s_registeredId;

	uint16_t pktSizes[PSTATS_MAXELEMCOUNT];
	uint8_t pktTcpFlgs[PSTATS_MAXELEMCOUNT];
	struct timeval pktTimestamps[PSTATS_MAXELEMCOUNT];
	int8_t pktDirs[PSTATS_MAXELEMCOUNT];
	uint16_t pktCount;
	uint32_t tcpSeq[2];
	uint32_t tcpAck[2];
	uint16_t tcpLen[2];
	uint8_t tcpFlg[2];

	typedef enum eHdrFieldID {
		PKT_SIZE = 1013,
		PKT_FLAGS = 1015,
		PKT_DIR = 1016,
		PKT_TMSTP = 1014
	} eHdrSemantic;

	static const uint32_t CESNET_PEM = 8057;

	RecordExtPSTATS()
		: RecordExt(s_registeredId)
	{
		pktCount = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_array_allocate(tmplt, record, F_PPI_PKT_TIMES, pktCount);
		ur_array_allocate(tmplt, record, F_PPI_PKT_LENGTHS, pktCount);
		ur_array_allocate(tmplt, record, F_PPI_PKT_FLAGS, pktCount);
		ur_array_allocate(tmplt, record, F_PPI_PKT_DIRECTIONS, pktCount);

		for (int i = 0; i < pktCount; i++) {
			ur_time_t ts
				= ur_time_from_sec_usec(pktTimestamps[i].tv_sec, pktTimestamps[i].tv_usec);
			ur_array_set(tmplt, record, F_PPI_PKT_TIMES, i, ts);
			ur_array_set(tmplt, record, F_PPI_PKT_LENGTHS, i, pktSizes[i]);
			ur_array_set(tmplt, record, F_PPI_PKT_FLAGS, i, pktTcpFlgs[i]);
			ur_array_set(tmplt, record, F_PPI_PKT_DIRECTIONS, i, pktDirs[i]);
		}
	}

	const char* getUnirecTmplt() const
	{
		return PSTATS_UNIREC_TEMPLATE;
	}
#endif // ifdef WITH_NEMEA

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int32_t bufferPtr;
		IpfixBasicList basiclist;
		basiclist.hdrEnterpriseNum = IpfixBasicList::CESNET_PEM;
		// Check sufficient size of buffer
		int reqSize = 4 * basiclist.headerSize() /* sizes, times, flags, dirs */
			+ pktCount * sizeof(uint16_t) /* sizes */ + 2 * pktCount * sizeof(uint32_t) /* times
																						   */
			+ pktCount /* flags */ + pktCount /* dirs */;

		if (reqSize > size) {
			return -1;
		}
		// Fill packet sizes
		bufferPtr = basiclist.fillBuffer(buffer, pktSizes, pktCount, (uint16_t) PKT_SIZE);
		// Fill timestamps
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			pktTimestamps,
			pktCount,
			(uint16_t) PKT_TMSTP);
		// Fill tcp flags
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			pktTcpFlgs,
			pktCount,
			(uint16_t) PKT_FLAGS);
		// Fill directions
		bufferPtr
			+= basiclist.fillBuffer(buffer + bufferPtr, pktDirs, pktCount, (uint16_t) PKT_DIR);

		return bufferPtr;
	} // fill_ipfix

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_PSTATS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfixTmplt;
	}
	std::string getText() const
	{
		std::ostringstream out;
		out << "ppisizes=(";
		for (int i = 0; i < pktCount; i++) {
			out << pktSizes[i];
			if (i != pktCount - 1) {
				out << ",";
			}
		}
		out << "),ppitimes=(";
		for (int i = 0; i < pktCount; i++) {
			out << pktTimestamps[i].tv_sec << "." << pktTimestamps[i].tv_usec;
			if (i != pktCount - 1) {
				out << ",";
			}
		}
		out << "),ppiflags=(";
		for (int i = 0; i < pktCount; i++) {
			out << (uint16_t) pktTcpFlgs[i];
			if (i != pktCount - 1) {
				out << ",";
			}
		}
		out << "),ppidirs=(";
		for (int i = 0; i < pktCount; i++) {
			out << (int16_t) pktDirs[i];
			if (i != pktCount - 1) {
				out << ",";
			}
		}
		out << ")";
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing PSTATS packets.
 */
class PSTATSPlugin : public ProcessPlugin {
public:
	PSTATSPlugin();
	~PSTATSPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new PSTATSOptParser(); }
	std::string getName() const { return "pstats"; }
	RecordExt* getExt() const { return new RecordExtPSTATS(); }
	ProcessPlugin* copy();
	int postCreate(Flow& rec, const Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);
	void updateRecord(RecordExtPSTATS* pstatsData, const Packet& pkt);
	void preExport(Flow& rec);

private:
	bool m_use_zeros;
	bool m_skip_dup_pkts;
};

} // namespace ipxp
#endif /* IPXP_PROCESS_PSTATS_HPP */
