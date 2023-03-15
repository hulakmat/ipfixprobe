/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2021-2022, CESNET z.s.p.o.
 */

/**
 * \file quic.cpp
 * \brief Plugin for enriching flows for quic data.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "quic.hpp"

namespace Ipxp {
int RecordExtQUIC::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("quic", []() { return new QUICPlugin(); });

	registerPlugin(&rec);
	RecordExtQUIC::s_registeredId = registerExtension();
}

QUICPlugin::QUICPlugin()
{
	m_quic_ptr = nullptr;
}

QUICPlugin::~QUICPlugin()
{
	close();
}

void QUICPlugin::init(const char* params) {}

void QUICPlugin::close()
{
	if (m_quic_ptr != nullptr) {
		delete m_quic_ptr;
	}
	m_quic_ptr = nullptr;
}

ProcessPlugin* QUICPlugin::copy()
{
	return new QUICPlugin(*this);
}

bool QUICPlugin::processQuic(RecordExtQUIC* quicData, const Packet& pkt)
{
	QUICParser processQuic;

	if (!processQuic.quicStart(pkt)) {
		return false;
	} else {
		processQuic.quicGetSni(quicData->sni);
		processQuic.quicGetUserAgent(quicData->userAgent);
		processQuic.quicGetVersion(quicData->quicVersion);
		return true;
	}
} // QUICPlugin::process_quic

int QUICPlugin::preCreate(Packet& pkt)
{
	return 0;
}

int QUICPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	addQuic(rec, pkt);
	return 0;
}

int QUICPlugin::preUpdate(Flow& rec, Packet& pkt)
{
	return 0;
}

int QUICPlugin::postUpdate(Flow& rec, const Packet& pkt)
{
	RecordExtQUIC* ext = (RecordExtQUIC*) rec.getExtension(RecordExtQUIC::s_registeredId);

	if (ext == nullptr) {
		return 0;
	}

	addQuic(rec, pkt);
	return 0;
}

void QUICPlugin::addQuic(Flow& rec, const Packet& pkt)
{
	if (m_quic_ptr == nullptr) {
		m_quic_ptr = new RecordExtQUIC();
	}

	if (processQuic(m_quic_ptr, pkt)) {
		rec.addExtension(m_quic_ptr);
		m_quic_ptr = nullptr;
	}
}

void QUICPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "QUIC plugin stats:" << std::endl;
		std::cout << "   Parsed SNI: " << m_parsed_initial << std::endl;
	}
}
} // namespace ipxp
