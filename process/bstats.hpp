/**
 * \file bstats.hpp
 * \brief Plugin for parsing bstats traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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

#ifndef IPXP_PROCESS_BSTATS_HPP
#define IPXP_PROCESS_BSTATS_HPP

#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

#define BSTATS_MAXELENCOUNT 15

// BURST CHARACTERISTIC
#define MINIMAL_PACKETS_IN_BURST 3 // in packets
#define MAXIMAL_INTERPKT_TIME                                                                      \
	1000 // in miliseconds
		 // maximal time between consecutive in-burst packets
#define BSTATS_SOURCE 0
#define BSTATS_DEST 1

#define BSTATS_UNIREC_TEMPLATE                                                                     \
	"SBI_BRST_PACKETS,SBI_BRST_BYTES,SBI_BRST_TIME_START,SBI_BRST_TIME_STOP,\
                                DBI_BRST_PACKETS,DBI_BRST_BYTES,DBI_BRST_TIME_START,DBI_BRST_TIME_STOP"

UR_FIELDS(
	uint32* SBI_BRST_BYTES,
	uint32* SBI_BRST_PACKETS,
	time* SBI_BRST_TIME_START,
	time* SBI_BRST_TIME_STOP,
	uint32* DBI_BRST_PACKETS,
	uint32* DBI_BRST_BYTES,
	time* DBI_BRST_TIME_START,
	time* DBI_BRST_TIME_STOP)

/**
 * \brief Flow record extension header for storing parsed BSTATS packets.
 */
struct RecordExtBSTATS : public RecordExt {
	typedef enum eHdrFieldID {
		S_PKTS = 1050,
		S_BYTES = 1051,
		S_START = 1052,
		S_STOP = 1053,
		D_PKTS = 1054,
		D_BYTES = 1055,
		D_START = 1056,
		D_STOP = 1057
	} eHdrFieldID;

	static int s_registeredId;

	uint16_t burst_count[2];
	uint8_t burstEmpty[2];

	uint32_t brstPkts[2][BSTATS_MAXELENCOUNT];
	uint32_t brstBytes[2][BSTATS_MAXELENCOUNT];
	struct timeval brstStart[2][BSTATS_MAXELENCOUNT];
	struct timeval brstEnd[2][BSTATS_MAXELENCOUNT];

	RecordExtBSTATS()
		: RecordExt(s_registeredId)
	{
		memset(burst_count, 0, 2 * sizeof(uint16_t));
		memset(burstEmpty, 0, 2 * sizeof(uint8_t));
		brstPkts[BSTATS_DEST][0] = 0;
		brstPkts[BSTATS_SOURCE][0] = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_time_t tsStart, tsStop;

		ur_array_allocate(tmplt, record, F_SBI_BRST_PACKETS, burst_count[BSTATS_SOURCE]);
		ur_array_allocate(tmplt, record, F_SBI_BRST_BYTES, burst_count[BSTATS_SOURCE]);
		ur_array_allocate(tmplt, record, F_SBI_BRST_TIME_START, burst_count[BSTATS_SOURCE]);
		ur_array_allocate(tmplt, record, F_SBI_BRST_TIME_STOP, burst_count[BSTATS_SOURCE]);

		ur_array_allocate(tmplt, record, F_DBI_BRST_PACKETS, burst_count[BSTATS_DEST]);
		ur_array_allocate(tmplt, record, F_DBI_BRST_BYTES, burst_count[BSTATS_DEST]);
		ur_array_allocate(tmplt, record, F_DBI_BRST_TIME_START, burst_count[BSTATS_DEST]);
		ur_array_allocate(tmplt, record, F_DBI_BRST_TIME_STOP, burst_count[BSTATS_DEST]);

		for (int i = 0; i < burst_count[BSTATS_SOURCE]; i++) {
			tsStart = ur_time_from_sec_usec(
				brstStart[BSTATS_SOURCE][i].tv_sec,
				brstStart[BSTATS_SOURCE][i].tv_usec);
			tsStop = ur_time_from_sec_usec(
				brstEnd[BSTATS_SOURCE][i].tv_sec,
				brstEnd[BSTATS_SOURCE][i].tv_usec);
			ur_array_set(tmplt, record, F_SBI_BRST_PACKETS, i, brstPkts[BSTATS_SOURCE][i]);
			ur_array_set(tmplt, record, F_SBI_BRST_BYTES, i, brstBytes[BSTATS_SOURCE][i]);
			ur_array_set(tmplt, record, F_SBI_BRST_TIME_START, i, tsStart);
			ur_array_set(tmplt, record, F_SBI_BRST_TIME_STOP, i, tsStop);
		}
		for (int i = 0; i < burst_count[BSTATS_DEST]; i++) {
			tsStart = ur_time_from_sec_usec(
				brstStart[BSTATS_DEST][i].tv_sec,
				brstStart[BSTATS_DEST][i].tv_usec);
			tsStop = ur_time_from_sec_usec(
				brstEnd[BSTATS_DEST][i].tv_sec,
				brstEnd[BSTATS_DEST][i].tv_usec);
			ur_array_set(tmplt, record, F_DBI_BRST_PACKETS, i, brstPkts[BSTATS_DEST][i]);
			ur_array_set(tmplt, record, F_DBI_BRST_BYTES, i, brstBytes[BSTATS_DEST][i]);
			ur_array_set(tmplt, record, F_DBI_BRST_TIME_START, i, tsStart);
			ur_array_set(tmplt, record, F_DBI_BRST_TIME_STOP, i, tsStop);
		}
	}

	const char* getUnirecTmplt() const
	{
		return BSTATS_UNIREC_TEMPLATE;
	}
#endif // ifdef WITH_NEMEA

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int32_t bufferPtr;
		IpfixBasicList basiclist;

		basiclist.hdrEnterpriseNum = IpfixBasicList::CESNET_PEM;
		// Check sufficient size of buffer
		int reqSize = 8 * basiclist.headerSize() /* sizes, times, flags, dirs */
			+ 2 * burst_count[BSTATS_SOURCE] * sizeof(uint32_t) /* bytes+sizes */
			+ 2 * burst_count[BSTATS_SOURCE] * sizeof(uint64_t) /* times_start + time_end */
			+ 2 * burst_count[BSTATS_DEST] * sizeof(uint32_t) /* bytes+sizes */
			+ 2 * burst_count[BSTATS_DEST] * sizeof(uint64_t) /* times_start + time_end */;

		if (reqSize > size) {
			return -1;
		}
		// Fill buffer
		bufferPtr = basiclist.fillBuffer(
			buffer,
			brstPkts[BSTATS_SOURCE],
			burst_count[BSTATS_SOURCE],
			(uint16_t) S_PKTS);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			brstBytes[BSTATS_SOURCE],
			burst_count[BSTATS_SOURCE],
			(uint16_t) S_BYTES);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			brstStart[BSTATS_SOURCE],
			burst_count[BSTATS_SOURCE],
			(uint16_t) S_START);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			brstEnd[BSTATS_SOURCE],
			burst_count[BSTATS_SOURCE],
			(uint16_t) S_STOP);

		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			brstPkts[BSTATS_DEST],
			burst_count[BSTATS_DEST],
			(uint16_t) D_PKTS);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			brstBytes[BSTATS_DEST],
			burst_count[BSTATS_DEST],
			(uint16_t) D_BYTES);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			brstStart[BSTATS_DEST],
			burst_count[BSTATS_DEST],
			(uint16_t) D_START);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			brstEnd[BSTATS_DEST],
			burst_count[BSTATS_DEST],
			(uint16_t) D_STOP);

		return bufferPtr;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_BSTATS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};
		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		char dirsC[2] = {'s', 'd'};
		int dirs[2] = {BSTATS_SOURCE, BSTATS_DEST};

		for (int j = 0; j < 2; j++) {
			int dir = dirs[j];
			out << dirsC[j] << "burstpkts=(";
			for (int i = 0; i < burst_count[dir]; i++) {
				out << brstPkts[dir][i];
				if (i != burst_count[dir] - 1) {
					out << ",";
				}
			}
			out << ")," << dirsC[j] << "burstbytes=(";
			for (int i = 0; i < burst_count[dir]; i++) {
				out << brstBytes[dir][i];
				if (i != burst_count[dir] - 1) {
					out << ",";
				}
			}
			out << ")," << dirsC[j] << "bursttime=(";
			for (int i = 0; i < burst_count[dir]; i++) {
				struct timeval start = brstStart[dir][i];
				struct timeval end = brstEnd[dir][i];
				out << start.tv_sec << "." << start.tv_usec << "-" << end.tv_sec << "."
					<< end.tv_usec;
				if (i != burst_count[dir] - 1) {
					out << ",";
				}
			}
			out << "),";
		}

		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing BSTATS packets.
 */
class BSTATSPlugin : public ProcessPlugin {
public:
	BSTATSPlugin();
	~BSTATSPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const
	{
		return new OptionsParser("bstats", "Compute packet bursts stats");
	}
	std::string getName() const { return "bstats"; }
	RecordExt* getExt() const { return new RecordExtBSTATS(); }
	ProcessPlugin* copy();

	int preCreate(Packet& pkt);
	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);
	void preExport(Flow& rec);

	static const struct timeval MIN_PACKET_IN_BURST;

private:
	void initializeNewBurst(RecordExtBSTATS* bstatsRecord, uint8_t direction, const Packet& pkt);
	void processBursts(RecordExtBSTATS* bstatsRecord, uint8_t direction, const Packet& pkt);
	void updateRecord(RecordExtBSTATS* bstatsRecord, const Packet& pkt);
	bool isLastRecordBurst(RecordExtBSTATS* bstatsRecord, uint8_t direction);
	bool belogsToLastRecord(RecordExtBSTATS* bstatsRecord, uint8_t direction, const Packet& pkt);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_BSTATS_HPP */
