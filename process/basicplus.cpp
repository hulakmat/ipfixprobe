/**
 * \file basicplus.cpp
 * \brief Plugin for parsing basicplus traffic.
 * \author Jiri Havranek <havranek@cesnet.cz>
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

#include <iostream>

#include "basicplus.hpp"

namespace Ipxp {

int RecordExtBASICPLUS::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("basicplus", []() { return new BASICPLUSPlugin(); });
	registerPlugin(&rec);
	RecordExtBASICPLUS::s_registeredId = registerExtension();
}

BASICPLUSPlugin::BASICPLUSPlugin() {}

BASICPLUSPlugin::~BASICPLUSPlugin()
{
	close();
}

void BASICPLUSPlugin::init(const char* params) {}

void BASICPLUSPlugin::close() {}

ProcessPlugin* BASICPLUSPlugin::copy()
{
	return new BASICPLUSPlugin(*this);
}

int BASICPLUSPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	RecordExtBASICPLUS* p = new RecordExtBASICPLUS();

	rec.addExtension(p);

	p->ipTtl[0] = pkt.ipTtl;
	p->ipFlg[0] = pkt.ipFlags;
	p->tcpMss[0] = pkt.tcpMss;
	p->tcpOpt[0] = pkt.tcpOptions;
	p->tcpWin[0] = pkt.tcpWindow;
	if (pkt.tcpFlags == 0x02) { // check syn packet
		p->tcpSynSize = pkt.ipLen;
	}

	return 0;
}

int BASICPLUSPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	RecordExtBASICPLUS* p
		= (RecordExtBASICPLUS*) rec.getExtension(RecordExtBASICPLUS::s_registeredId);
	uint8_t dir = pkt.sourcePkt ? 0 : 1;

	if (p->ipTtl[dir] < pkt.ipTtl) {
		p->ipTtl[dir] = pkt.ipTtl;
	}
	if (dir && !p->dstFilled) {
		p->ipTtl[1] = pkt.ipTtl;
		p->ipFlg[1] = pkt.ipFlags;
		p->tcpMss[1] = pkt.tcpMss;
		p->tcpOpt[1] = pkt.tcpOptions;
		p->tcpWin[1] = pkt.tcpWindow;
		p->dstFilled = true;
	}
	return 0;
}

} // namespace ipxp
