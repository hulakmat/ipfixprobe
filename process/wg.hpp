/**
 * \file wg.hpp
 * \brief Plugin for parsing wg traffic.
 * \author Pavel Valach <valacpav@fit.cvut.cz>
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

#ifndef IPXP_PROCESS_WG_HPP
#define IPXP_PROCESS_WG_HPP

#include <sstream>
#include <string>

#ifdef WITH_NEMEA
#include "fields.h"
#endif

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/process.hpp>

namespace Ipxp {

/**
 * \brief WireGuard packet types.
 */
#define WG_PACKETTYPE_INIT_TO_RESP 0x01 /**< Initiator to Responder message **/
#define WG_PACKETTYPE_RESP_TO_INIT 0x02 /**< Responder to Initiator message **/
#define WG_PACKETTYPE_COOKIE_REPLY 0x03 /**< Cookie Reply (under load) message **/
#define WG_PACKETTYPE_TRANSPORT_DATA 0x04 /**< Transport Data message **/

/**
 * \brief WireGuard UDP payload (minimum) lengths.
 */
#define WG_PACKETLEN_INIT_TO_RESP 148
#define WG_PACKETLEN_RESP_TO_INIT 92
#define WG_PACKETLEN_COOKIE_REPLY 64
#define WG_PACKETLEN_MIN_TRANSPORT_DATA 32

#define WG_UNIREC_TEMPLATE "WG_CONF_LEVEL,WG_SRC_PEER,WG_DST_PEER"

UR_FIELDS(uint8 WG_CONF_LEVEL, uint32 WG_SRC_PEER, uint32 WG_DST_PEER)

/**
 * \brief Flow record extension header for storing parsed WG packets.
 */
struct RecordExtWG : public RecordExt {
	static int s_registeredId;

	uint8_t possibleWg;
	uint32_t srcPeer;
	uint32_t dstPeer;

	RecordExtWG()
		: RecordExt(s_registeredId)
	{
		possibleWg = 0;
		srcPeer = 0;
		dstPeer = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_WG_CONF_LEVEL, possibleWg);
		ur_set(tmplt, record, F_WG_SRC_PEER, srcPeer);
		ur_set(tmplt, record, F_WG_DST_PEER, dstPeer);
	}

	const char* getUnirecTmplt() const
	{
		return WG_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		int requiredLen = 0;

		requiredLen += sizeof(possibleWg); // WG_CONF_LEVEL
		requiredLen += sizeof(srcPeer); // WG_SRC_PEER
		requiredLen += sizeof(dstPeer); // WG_DST_PEER

		if (requiredLen > size) {
			return -1;
		}

		memcpy(buffer, &possibleWg, sizeof(possibleWg));
		buffer += sizeof(possibleWg);
		memcpy(buffer, &srcPeer, sizeof(srcPeer));
		buffer += sizeof(srcPeer);
		memcpy(buffer, &dstPeer, sizeof(dstPeer));
		buffer += sizeof(dstPeer);

		return requiredLen;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_WG_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "wgconf=" << (uint16_t) possibleWg << ",wgsrcpeer=" << srcPeer
			<< ",wgdstpeer=" << dstPeer;
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing WG packets.
 */
class WGPlugin : public ProcessPlugin {
public:
	WGPlugin();
	~WGPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const { return new OptionsParser("wg", "Parse WireGuard traffic"); }
	std::string getName() const { return "wg"; }
	RecordExt* getExt() const { return new RecordExtWG(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	void preExport(Flow& rec);
	void finish(bool printStats);

private:
	RecordExtWG* m_preallocated_record; /**< Preallocated instance of record to use */
	bool m_flow_flush; /**< Instructs the engine to create new flow, during pre_update. */
	uint32_t m_total; /**< Total number of processed packets. */
	uint32_t m_identified; /**< Total number of identified WireGuard packets. */

	bool parseWg(const char* data, unsigned int payloadLen, bool sourcePkt, RecordExtWG* ext);
	int addExtWg(const char* data, unsigned int payloadLen, bool sourcePkt, Flow& rec);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_WG_HPP */
