/**
 * \file idpcontent.hpp
 * \brief Plugin for parsing idpcontent traffic.
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
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

#ifndef IPXP_PROCESS_IDPCONTENT_HPP
#define IPXP_PROCESS_IDPCONTENT_HPP

#include <cstring>
#include <iomanip>
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

#define IDPCONTENT_SIZE 100
#define EXPORTED_PACKETS 2
#define IDP_CONTENT_INDEX 0
#define IDP_CONTENT_REV_INDEX 1

#define IDPCONTENT_UNIREC_TEMPLATE "IDP_CONTENT,IDP_CONTENT_REV"

UR_FIELDS(bytes IDP_CONTENT, bytes IDP_CONTENT_REV)

/**
 * \brief Flow record extension header for storing parsed IDPCONTENT packets.
 */

struct IdpcontentArray {
	IdpcontentArray()
		: size(0) {};
	uint8_t size;
	uint8_t data[IDPCONTENT_SIZE];
};

struct RecordExtIDPCONTENT : public RecordExt {
	static int s_registeredId;

	uint8_t pktExportFlg[EXPORTED_PACKETS];
	IdpcontentArray idps[EXPORTED_PACKETS];

	RecordExtIDPCONTENT()
		: RecordExt(s_registeredId)
	{
	}

#ifdef WITH_NEMEA
	virtual void fillUnirec(ur_template_t* tmplt, void* record)
	{
		ur_set_var(
			tmplt,
			record,
			F_IDP_CONTENT,
			idps[IDP_CONTENT_INDEX].data,
			idps[IDP_CONTENT_INDEX].size);
		ur_set_var(
			tmplt,
			record,
			F_IDP_CONTENT_REV,
			idps[IDP_CONTENT_REV_INDEX].data,
			idps[IDP_CONTENT_REV_INDEX].size);
	}

	const char* getUnirecTmplt() const
	{
		return IDPCONTENT_UNIREC_TEMPLATE;
	}
#endif

	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		uint32_t pos = 0;

		if (idps[IDP_CONTENT_INDEX].size + idps[IDP_CONTENT_REV_INDEX].size + 2 > size) {
			return -1;
		}
		for (int i = 0; i < EXPORTED_PACKETS; i++) {
			buffer[pos++] = idps[i].size;
			memcpy(buffer + pos, idps[i].data, idps[i].size);
			pos += idps[i].size;
		}

		return pos;
	}

	const char** getIpfixTmplt() const
	{
		static const char* ipfixTmplt[] = {IPFIX_IDPCONTENT_TEMPLATE(IPFIX_FIELD_NAMES) nullptr};

		return ipfixTmplt;
	}

	std::string getText() const
	{
		std::ostringstream out;
		out << "idpsrc=";
		for (size_t i = 0; i < idps[IDP_CONTENT_INDEX].size; i++) {
			out << std::hex << std::setw(2) << std::setfill('0') << idps[IDP_CONTENT_INDEX].data[i];
		}
		out << ",idpdst=";
		for (size_t i = 0; i < idps[IDP_CONTENT_REV_INDEX].size; i++) {
			out << std::hex << std::setw(2) << std::setfill('0')
				<< idps[IDP_CONTENT_REV_INDEX].data[i];
		}
		return out.str();
	}
};

/**
 * \brief Flow cache plugin for parsing IDPCONTENT packets.
 */
class IDPCONTENTPlugin : public ProcessPlugin {
public:
	IDPCONTENTPlugin();
	~IDPCONTENTPlugin();
	void init(const char* params);
	void close();
	OptionsParser* getParser() const
	{
		return new OptionsParser("idpcontent", "Parse first bytes of flow payload");
	}
	std::string getName() const { return "idpcontent"; }
	RecordExt* getExt() const { return new RecordExtIDPCONTENT(); }
	ProcessPlugin* copy();

	int postCreate(Flow& rec, const Packet& pkt);
	int postUpdate(Flow& rec, const Packet& pkt);
	void updateRecord(RecordExtIDPCONTENT* pstatsData, const Packet& pkt);
};

} // namespace ipxp
#endif /* IPXP_PROCESS_IDPCONTENT_HPP */
