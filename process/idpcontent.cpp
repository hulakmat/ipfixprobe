/**
 * \file idpcontent.cpp
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

#include <iostream>

#include "idpcontent.hpp"

namespace Ipxp {

int RecordExtIDPCONTENT::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("idpcontent", []() { return new IDPCONTENTPlugin(); });
	registerPlugin(&rec);
	RecordExtIDPCONTENT::s_registeredId = registerExtension();
}

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

IDPCONTENTPlugin::IDPCONTENTPlugin() {}

IDPCONTENTPlugin::~IDPCONTENTPlugin()
{
	close();
}

void IDPCONTENTPlugin::init(const char* params) {}

void IDPCONTENTPlugin::close() {}

ProcessPlugin* IDPCONTENTPlugin::copy()
{
	return new IDPCONTENTPlugin(*this);
}

void IDPCONTENTPlugin::updateRecord(RecordExtIDPCONTENT* idpcontentData, const Packet& pkt)
{
	// create ptr into buffers from packet directions
	uint8_t paketDirection = (uint8_t) (!pkt.sourcePkt);

	// Check zero-packets and be sure, that the exported content is from both directions
	if (idpcontentData->pktExportFlg[paketDirection] != 1 && pkt.payloadLen > 0) {
		idpcontentData->idps[paketDirection].size = MIN(IDPCONTENT_SIZE, pkt.payloadLen);
		memcpy(
			idpcontentData->idps[paketDirection].data,
			pkt.payload,
			idpcontentData->idps[paketDirection].size);
		idpcontentData->pktExportFlg[paketDirection] = 1;
	}
}

int IDPCONTENTPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	RecordExtIDPCONTENT* idpcontentData = new RecordExtIDPCONTENT();
	memset(idpcontentData->pktExportFlg, 0, 2 * sizeof(uint8_t));
	rec.addExtension(idpcontentData);

	updateRecord(idpcontentData, pkt);
	return 0;
}

int IDPCONTENTPlugin::postUpdate(Flow& rec, const Packet& pkt)
{
	RecordExtIDPCONTENT* idpcontentData
		= static_cast<RecordExtIDPCONTENT*>(rec.getExtension(RecordExtIDPCONTENT::s_registeredId));
	updateRecord(idpcontentData, pkt);
	return 0;
}

} // namespace ipxp
