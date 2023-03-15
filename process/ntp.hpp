/**
 * \file ntp.hpp
 * \author Alejandro Robledo <robleale@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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

#ifndef IPXP_PROCESS_NTP_HPP
#define IPXP_PROCESS_NTP_HPP

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

#ifdef WITH_NEMEA
#include <fields.h>
#endif

#include <stdio.h>

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

#define NTP_UNIREC_TEMPLATE                                                                        \
	"NTP_LEAP,NTP_VERSION,NTP_MODE,NTP_STRATUM,NTP_POLL,NTP_PRECISION,NTP_DELAY,NTP_DISPERSION,"   \
	"NTP_REF_ID,NTP_REF,NTP_ORIG,NTP_RECV,NTP_SENT"

UR_FIELDS(
	uint8 NTP_LEAP,
	uint8 NTP_VERSION,
	uint8 NTP_MODE,
	uint8 NTP_STRATUM,
	uint8 NTP_POLL,
	uint8 NTP_PRECISION,
	uint32 NTP_DELAY,
	uint32 NTP_DISPERSION,
	string NTP_REF_ID,
	string NTP_REF,
	string NTP_ORIG,
	string NTP_RECV,
	string NTP_SENT)

#define NTP_FIELD_IP 16
#define NTP_FIELD_LEN64 30

const char g_NTP_RefID_INIT[] = "73.78.73.84"; /*Value of NTP reference ID INIT*/
const char g_INIT[] = "INIT";
const char g_NTP_RefID_STEP[] = "83.84.69.80"; /*Value of NTP reference ID STEP*/
const char g_STEP[] = "STEP";
const char g_NTP_RefID_DENY[] = "68.69.78.89"; /*Value of NTP reference ID DENY*/
const char g_DENY[] = "DENY";
const char g_NTP_RefID_RATE[] = "82.65.84.69"; /*Value of NTP reference ID RATE*/
const char g_RATE[] = "RATE";
const char g_OTHER[] = "OTHER"; /*OTHER Value of NTP reference ID*/

/**
 *\brief Flow record extension header for storing NTP fields.
 */
struct RecordExtNTP : public RecordExt {
	static int s_registeredId;

	uint8_t leap;
	uint8_t version;
	uint8_t mode;
	uint8_t stratum;
	uint8_t poll;
	uint8_t precision;
	uint32_t delay;
	uint32_t dispersion;
	char referenceId[NTP_FIELD_IP];
	char reference[NTP_FIELD_LEN64];
	char origin[NTP_FIELD_LEN64];
	char receive[NTP_FIELD_LEN64];
	char sent[NTP_FIELD_LEN64];

	/**
	 *\brief Constructor.
	 */
	RecordExtNTP()
		: RecordExt(s_registeredId)
	{
		leap = 9;
		version = 9;
		mode = 9;
		stratum = 9;
		poll = 9;
		precision = 9;
		delay = 9;
		dispersion = 9;
		referenceId[0] = 9;
		reference[0] = 9;
		origin[0] = 9;
		receive[0] = 9;
		sent[0] = 9;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_NTP_LEAP, leap);
		ur_set(tmplt, record, F_NTP_VERSION, version);
		ur_set(tmplt, record, F_NTP_MODE, mode);
		ur_set(tmplt, record, F_NTP_STRATUM, stratum);
		ur_set(tmplt, record, F_NTP_POLL, poll);
		ur_set(tmplt, record, F_NTP_PRECISION, precision);
		ur_set(tmplt, record, F_NTP_DELAY, delay);
		ur_set(tmplt, record, F_NTP_DISPERSION, dispersion);
		ur_set_string(tmplt, record, F_NTP_REF_ID, referenceId);
		ur_set_string(tmplt, record, F_NTP_REF, reference);
		ur_set_string(tmplt, record, F_NTP_ORIG, origin);
		ur_set_string(tmplt, record, F_NTP_RECV, receive);
		ur_set_string(tmplt, record, F_NTP_SENT, sent);
	}

	const char* getUnirecTmplt() const
	{
		return NTP_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int length, totalLength = 14;

		if (totalLength > size) {
			return -1;
		}
		*(uint8_t*) (buffer) = leap;
		*(uint8_t*) (buffer + 1) = version;
		*(uint8_t*) (buffer + 2) = mode;
		*(uint8_t*) (buffer + 3) = stratum;
		*(uint8_t*) (buffer + 4) = poll;
		*(uint8_t*) (buffer + 5) = precision;
		*(uint32_t*) (buffer + 6) = ntohl(delay);
		*(uint32_t*) (buffer + 10) = ntohl(dispersion);

		length = strlen(referenceId);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, referenceId, length);
		totalLength += length + 1;

		length = strlen(reference);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, reference, length);
		totalLength += length + 1;

		length = strlen(origin);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, origin, length);
		totalLength += length + 1;

		length = strlen(receive);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, receive, length);
		totalLength += length + 1;

		length = strlen(sent);
		if (totalLength + length + 1 > size) {
			return -1;
		}
		buffer[totalLength] = length;
		memcpy(buffer + totalLength + 1, sent, length);
		totalLength += length + 1;

		return totalLength;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_NTP_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "leap=" << (uint16_t) leap << ",version=" << (uint16_t) version
			<< ",mode=" << (uint16_t) mode << ",stratum=" << (uint16_t) stratum
			<< ",poll=" << (uint16_t) poll << ",precision=" << (uint16_t) precision
			<< ",delay=" << delay << ",dispersion=" << dispersion << ",referenceid=\""
			<< referenceId << "\""
			<< ",reference=\"" << reference << "\""
			<< ",origin=\"" << origin << "\""
			<< ",receive=\"" << receive << "\""
			<< ",sent=\"" << sent << "\"";
		return out.str();
	}
};

/**
 *\brief Flow cache plugin for parsing DNS packets.
 */
class NTPPlugin : public ProcessPlugin {
public:
	NTPPlugin();
	~NTPPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new OptionsParser("ntp", "Parse NTP traffic"); }
	std::string getName() const { return "ntp"; }
	RecordExt* getExt() const { return new RecordExtNTP(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	void finish(bool printStats);

private:
	uint32_t m_requests; /**< Total number of parsed NTP queries. */
	uint32_t m_responses; /**< Total number of parsed NTP responses. */
	uint32_t m_total; /**< Total number of parsed DNS packets. */

	bool parseNtp(const Packet& pkt, RecordExtNTP* ntpDataExt);
	void addExtNtp(Flow& rec, const Packet& pkt);
	std::string
	parseTimestamp(const Packet& pkt, uint16_t p1, uint16_t p4, uint16_t p5, uint16_t p8);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_NTP_HPP */
