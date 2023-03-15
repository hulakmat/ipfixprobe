/**
 * \file phists.hpp
 * \brief Plugin for parsing phists traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
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

#ifndef IPXP_PROCESS_PHISTS_HPP
#define IPXP_PROCESS_PHISTS_HPP

#include <limits>
#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-basiclist.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

#ifndef PHISTS_MINLEN
#define PHISTS_MINLEN 1
#endif

#define HISTOGRAM_SIZE 8

#define PHISTS_UNIREC_TEMPLATE "S_PHISTS_SIZES,S_PHISTS_IPT,D_PHISTS_SIZES,D_PHISTS_IPT"

UR_FIELDS(
	uint32* S_PHISTS_SIZES,
	uint32* S_PHISTS_IPT,
	uint32* D_PHISTS_SIZES,
	uint32* D_PHISTS_IPT)

class PHISTSOptParser : public OptionsParser {
public:
	bool mIncludeZeroes;

	PHISTSOptParser()
		: OptionsParser("phists", "Processing plugin for packet histograms")
		, mIncludeZeroes(false)
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
	}
};

/**
 * \brief Flow record extension header for storing parsed PHISTS packets.
 */
struct RecordExtPHISTS : public RecordExt {
	static int s_registeredId;

	typedef enum eHdrFieldID {
		SPhistsSizes = 1060,
		SPhistsIpt = 1061,
		DPhistsSizes = 1062,
		DPhistsIpt = 1063
	} eHdrSemantic;

	uint32_t sizeHist[2][HISTOGRAM_SIZE];
	uint32_t iptHist[2][HISTOGRAM_SIZE];
	uint32_t lastTs[2];

	RecordExtPHISTS()
		: RecordExt(s_registeredId)
	{
		// inicializing histograms with zeros
		for (int i = 0; i < 2; i++) {
			memset(sizeHist[i], 0, sizeof(uint32_t) * HISTOGRAM_SIZE);
			memset(iptHist[i], 0, sizeof(uint32_t) * HISTOGRAM_SIZE);
			lastTs[i] = 0;
		}
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_array_allocate(tmplt, record, F_S_PHISTS_SIZES, HISTOGRAM_SIZE);
		ur_array_allocate(tmplt, record, F_S_PHISTS_IPT, HISTOGRAM_SIZE);
		ur_array_allocate(tmplt, record, F_D_PHISTS_SIZES, HISTOGRAM_SIZE);
		ur_array_allocate(tmplt, record, F_D_PHISTS_IPT, HISTOGRAM_SIZE);
		for (int i = 0; i < HISTOGRAM_SIZE; i++) {
			ur_array_set(tmplt, record, F_S_PHISTS_SIZES, i, sizeHist[0][i]);
			ur_array_set(tmplt, record, F_S_PHISTS_IPT, i, iptHist[0][i]);
			ur_array_set(tmplt, record, F_D_PHISTS_SIZES, i, sizeHist[1][i]);
			ur_array_set(tmplt, record, F_D_PHISTS_IPT, i, iptHist[1][i]);
		}
	}

	const char* getUnirecTmplt() const
	{
		return PHISTS_UNIREC_TEMPLATE;
	}
#endif // ifdef WITH_NEMEA

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int32_t bufferPtr;
		IpfixBasicList basiclist;

		basiclist.hdrEnterpriseNum = IpfixBasicList::CESNET_PEM;
		// Check sufficient size of buffer
		int reqSize = 4 * basiclist.headerSize() /* sizes, times, flags, dirs */
			+ 4 * HISTOGRAM_SIZE * sizeof(uint32_t); /* sizes */

		if (reqSize > size) {
			return -1;
		}
		// Fill sizes
		// fill buffer with basic list header and SPhistsSizes
		bufferPtr
			= basiclist.fillBuffer(buffer, sizeHist[0], HISTOGRAM_SIZE, (uint32_t) SPhistsSizes);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			sizeHist[1],
			HISTOGRAM_SIZE,
			(uint32_t) DPhistsSizes);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			iptHist[0],
			HISTOGRAM_SIZE,
			(uint32_t) SPhistsIpt);
		bufferPtr += basiclist.fillBuffer(
			buffer + bufferPtr,
			iptHist[1],
			HISTOGRAM_SIZE,
			(uint32_t) DPhistsIpt);

		return bufferPtr;
	} // fill_ipfix

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_PHISTS_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		char dirsC[2] = {'s', 'd'};

		for (int dir = 0; dir < 2; dir++) {
			out << dirsC[dir] << "phistsize=(";
			for (int i = 0; i < HISTOGRAM_SIZE; i++) {
				out << sizeHist[dir][i];
				if (i != HISTOGRAM_SIZE - 1) {
					out << ",";
				}
			}
			out << ")," << dirsC[dir] << "phistipt=(";
			for (int i = 0; i < HISTOGRAM_SIZE; i++) {
				out << iptHist[dir][i];
				if (i != HISTOGRAM_SIZE - 1) {
					out << ",";
				}
			}
			out << "),";
		}
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing PHISTS packets.
 */
class PHISTSPlugin : public ProcessPlugin {
public:
	PHISTSPlugin();
	~PHISTSPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new PHISTSOptParser(); }
	std::string getName() const { return "phists"; }
	RecordExt* getExt() const { return new RecordExtPHISTS(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);

private:
	bool m_use_zeros;

	void updateRecord(RecordExtPHISTS* phistsData, const Packet& pkt);
	void updateHist(RecordExtPHISTS* phistsData, uint32_t value, uint32_t* histogram);
	void preExport(Flow& rec);
	uint64_t
	calculateIpt(RecordExtPHISTS* phistsData, const struct timeval tv, uint8_t direction);

	static const uint32_t LOG2_LOOKUP32[32];

	static inline uint32_t fastlog232(uint32_t value)
	{
		value |= value >> 1;
		value |= value >> 2;
		value |= value >> 4;
		value |= value >> 8;
		value |= value >> 16;
		return LOG2_LOOKUP32[(uint32_t) (value * 0x07C4ACDD) >> 27];
	}

	static inline uint32_t noOverflowIncrement(uint32_t value)
	{
		if (value == std::numeric_limits<uint32_t>::max()) {
			return value;
		}
		return value + 1;
	}
};

} // namespace ipxp
#endif /* IPXP_PROCESS_PHISTS_HPP */
