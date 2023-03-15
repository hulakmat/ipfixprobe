/**
 * \file ovpn.hpp
 * \brief Plugin for parsing ovpn traffic.
 * \author Karel Hynek <hynekkar@fit.cvut.cz>
 * \author Martin Ctrnacty <ctrnama2@fit.cvut.cz>
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

#ifndef IPXP_PROCESS_OVPN_HPP
#define IPXP_PROCESS_OVPN_HPP

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

#define OVPN_UNIREC_TEMPLATE "OVPN_CONF_LEVEL"

UR_FIELDS(uint8 OVPN_CONF_LEVEL)

/**
 * \brief Flow record extension header for storing parsed VPNDETECTOR packets.
 */
struct RecordExtOVPN : RecordExt {
	static int s_registeredId;

	uint8_t possibleVpn;
	uint32_t pktCnt;
	uint32_t dataPktCnt;
	int32_t invalidPktCnt;
	uint32_t status;
	ipaddr_t clientIp;

	RecordExtOVPN()
		: RecordExt(s_registeredId)
	{
		possibleVpn = 0;
		pktCnt = 0;
		dataPktCnt = 0;
		invalidPktCnt = 0;
		status = 0;
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set(tmplt, record, F_OVPN_CONF_LEVEL, possibleVpn);
	}

	const char* getUnirecTmplt() const
	{
		return OVPN_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		if (size < 1) {
			return -1;
		}
		buffer[0] = (uint8_t) possibleVpn;
		return 1;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_OVPN_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "ovpnconf=" << (uint16_t) possibleVpn;
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing VPNDETECTOR packets.
 */
class OVPNPlugin : public ProcessPlugin {
public:
	OVPNPlugin();
	~OVPNPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const
	{
		return new OptionsParser("ovpn", "OpenVPN detector plugin");
	}
	std::string getName() const { return "ovpn"; }
	RecordExt* getExt() const { return new RecordExtOVPN(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int preUpdate(Flow& rec, Packet& pkt);
	void updateRecord(RecordExtOVPN* vpnData, const Packet& pkt);
	void preExport(Flow& rec);

	typedef enum e_ip_proto_nbr { TCP = 6, UDP = 17 } e_ip_proto_nbr;

	static const uint32_t C_UDP_OPCODE_INDEX = 0;
	static const uint32_t C_TCP_OPCODE_INDEX = 2;
	static const uint32_t MIN_PCKT_TRESHOLD = 20;
	static constexpr float DATA_PCKT_TRESHOLD = 0.6f;
	static const int32_t INVALID_PCKT_TRESHOLD = 4;
	static const uint32_t MIN_OPCODE = 1;
	static const uint32_t MAX_OPCODE = 10;
	static const uint32_t P_CONTROL_HARD_RESET_CLIENT_V1
		= 1; /* initial key from client, forget previous state */
	static const uint32_t P_CONTROL_HARD_RESET_SERVER_V1
		= 2; /* initial key from server, forget previous state */
	static const uint32_t P_CONTROL_SOFT_RESET_V1
		= 3; /* new key, graceful transition from old to new key */
	static const uint32_t P_CONTROL_V1 = 4; /* control channel packet (usually tls ciphertext) */
	static const uint32_t P_ACK_V1 = 5; /* acknowledgement for packets received */
	static const uint32_t P_DATA_V1 = 6; /* data channel packet */
	static const uint32_t P_DATA_V2 = 9; /* data channel packet with peer-id */
	static const uint32_t P_CONTROL_HARD_RESET_CLIENT_V2
		= 7; /* initial key from client, forget previous state */
	static const uint32_t P_CONTROL_HARD_RESET_SERVER_V2
		= 8; /* initial key from server, forget previous state */
	static const uint32_t P_CONTROL_HARD_RESET_CLIENT_V3
		= 10; /* initial key from client, forget previous state */
	static const uint32_t STATUS_NULL = 0;
	static const uint32_t STATUS_RESET_CLIENT = 1;
	static const uint32_t STATUS_RESET_SERVER = 2;
	static const uint32_t STATUS_ACK = 3;
	static const uint32_t STATUS_CLIENT_HELLO = 4;
	static const uint32_t STATUS_SERVER_HELLO = 5;
	static const uint32_t STATUS_CONTROL_ACK = 6;
	static const uint32_t STATUS_DATA = 7;

private:
	bool compareIp(ipaddr_t ip1, ipaddr_t ip2, uint8_t ipVersion);
	bool checkSslClientHello(const Packet& pkt, uint8_t opcodeindex);
	bool checkSslServerHello(const Packet& pkt, uint8_t opcodeindex);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_OVPN_HPP */
