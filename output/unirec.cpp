/**
 * \file unirec.cpp
 * \brief Flow exporter converting flows to UniRec and sending them to TRAP ifc
 * \author Vaclav Bartos <bartos@cesnet.cz>
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2014
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2014-2016 CESNET
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

#include <config.h>

#ifdef WITH_NEMEA

#include <algorithm>
#include <libtrap/trap.h>
#include <string>
#include <unirec/unirec.h>
#include <vector>

#include "fields.h"
#include "unirec.hpp"

namespace Ipxp {

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("unirec", []() { return new UnirecExporter(); });
	registerPlugin(&rec);
}

#define BASIC_FLOW_TEMPLATE                                                                        \
	"SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,PACKETS_REV,BYTES_REV,TIME_FIRST,"     \
	"TIME_LAST,TCP_FLAGS,TCP_FLAGS_REV,DIR_BIT_FIELD,SRC_MAC,DST_MAC" /* LINK_BIT_FIELD or ODID    \
																		 will be added at init. */

#define PACKET_TEMPLATE "SRC_MAC,DST_MAC,ETHERTYPE,TIME"

UR_FIELDS(
	ipaddr DST_IP,
	ipaddr SRC_IP,
	uint64 BYTES,
	uint64 BYTES_REV,
	uint64 LINK_BIT_FIELD,
	uint32 ODID,
	time TIME_FIRST,
	time TIME_LAST,
	uint32 PACKETS,
	uint32 PACKETS_REV,
	uint16 DST_PORT,
	uint16 SRC_PORT,
	uint8 DIR_BIT_FIELD,
	uint8 PROTOCOL,
	uint8 TCP_FLAGS,
	uint8 TCP_FLAGS_REV,

	macaddr SRC_MAC,
	macaddr DST_MAC)

/**
 * \brief Constructor.
 */
UnirecExporter::UnirecExporter()
	: m_basic_idx(-1)
	, m_ext_cnt(0)
	, m_ifc_map(nullptr)
	, m_tmplts(nullptr)
	, m_records(nullptr)
	, m_ifc_cnt(0)
	, m_ext_id_flgs(nullptr)
	, m_eof(false)
	, m_odid(false)
	, m_link_bit_field(0)
	, m_dir_bit_field(0)
{
}

UnirecExporter::~UnirecExporter()
{
	close();
}

/**
 * \brief Count trap interfaces.
 * \param [in] argc Number of parameters.
 * \param [in] argv Pointer to parameters.
 * \return Number of trap interfaces.
 */
static int countTrapInterfaces(const char* spec)
{
	int ifcCnt = 1;
	if (spec != nullptr) {
		while (*spec) { // Count number of specified interfaces.
			if (*(spec++) == TRAP_IFC_DELIMITER) {
				ifcCnt++;
			}
		}
		return ifcCnt;
	}

	return ifcCnt;
}

int UnirecExporter::initTrap(std::string& ifcs, int verbosity)
{
	trap_ifc_spec_t ifcSpec;
	std::vector<char> specStr(ifcs.c_str(), ifcs.c_str() + ifcs.size() + 1);
	char* argv[] = {"-i", specStr.data()};
	int argc = 2;
	int ifcCnt = countTrapInterfaces(ifcs.c_str());

	if (trap_parse_params(&argc, argv, &ifcSpec) != TRAP_E_OK) {
		trap_free_ifc_spec(ifcSpec);
		std::string errMsg = "parsing parameters for TRAP failed";
		if (trap_last_error_msg) {
			errMsg += std::string(": ") + trap_last_error_msg;
		}
		throw PluginError(errMsg);
	}
	trap_module_info_t moduleInfo = {"ipfixprobe", "Output plugin for ipfixprobe", 0, ifcCnt};
	if (trap_init(&moduleInfo, ifcSpec) != TRAP_E_OK) {
		trap_free_ifc_spec(ifcSpec);
		std::string errMsg = "error in TRAP initialization: ";
		if (trap_last_error_msg) {
			errMsg += std::string(": ") + trap_last_error_msg;
		}
		throw PluginError(errMsg);
	}
	trap_free_ifc_spec(ifcSpec);

	if (verbosity > 0) {
		trap_set_verbose_level(verbosity - 1);
	}
	for (int i = 0; i < ifcCnt; i++) {
		trap_ifcctl(TRAPIFC_OUTPUT, i, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
	}
	return ifcCnt;
}

void UnirecExporter::init(const char* params)
{
	UnirecOptParser parser;
	try {
		parser.parse(params);
	} catch (ParserError& e) {
		throw PluginError(e.what());
	}

	if (parser.mHelp) {
		trap_print_ifc_spec_help();
		throw PluginExit();
	}
	if (parser.mIfc.empty()) {
		throw PluginError("specify libtrap interface specifier");
	}
	m_odid = parser.mOdid;
	m_eof = parser.mEof;
	m_link_bit_field = parser.mId;
	m_dir_bit_field = parser.mDir;
	m_group_map = parser.mIfcMap;
	m_ifc_cnt = initTrap(parser.mIfc, parser.mVerbose);
	m_ext_cnt = getExtensionCnt();

	try {
		m_tmplts = new ur_template_t*[m_ifc_cnt];
		m_records = new void*[m_ifc_cnt];
		m_ifc_map = new int[m_ext_cnt];
		m_ext_id_flgs = new int[m_ext_cnt];
	} catch (std::bad_alloc& e) {
		throw PluginError("not enough memory");
	}
	for (size_t i = 0; i < m_ifc_cnt; i++) {
		m_tmplts[i] = nullptr;
		m_records[i] = nullptr;
	}
	for (size_t i = 0; i < m_ext_cnt; i++) {
		m_ifc_map[i] = -1;
	}
}

void UnirecExporter::createTmplt(int ifcIdx, const char* tmpltStr)
{
	char* error = nullptr;
	m_tmplts[ifcIdx] = ur_create_output_template(ifcIdx, tmpltStr, &error);
	if (m_tmplts[ifcIdx] == nullptr) {
		std::string tmp = error;
		free(error);
		freeUnirecResources();
		throw PluginError(tmp);
	}
}

void UnirecExporter::init(const char* params, Plugins& plugins)
{
	init(params);

	std::string basicTmplt = BASIC_FLOW_TEMPLATE;
	if (m_odid) {
		basicTmplt += ",ODID";
	} else {
		basicTmplt += ",LINK_BIT_FIELD";
	}

	if (m_group_map.empty()) {
		if (m_ifc_cnt == 1 && plugins.empty()) {
			m_basic_idx = 0;

			createTmplt(m_basic_idx, basicTmplt.c_str());
		} else if (m_ifc_cnt == 1 && plugins.size() == 1) {
			m_group_map[0] = std::vector<std::string>({plugins[0].first});
		} else {
			throw PluginError("specify plugin-interface mapping");
		}
	}

	if (m_ifc_cnt != 1 && m_ifc_cnt != m_group_map.size()) {
		throw PluginError("number of interfaces and plugin groups differ");
	}

	for (auto& m : m_group_map) {
		unsigned ifcIdx = m.first;
		std::vector<std::string>& group = m.second;

		// Find plugin for each plugin in group
		std::vector<ProcessPlugin*> pluginGroup;
		for (auto& g : group) {
			ProcessPlugin* plugin = nullptr;
			for (auto& p : plugins) {
				std::string name = p.first;
				if (g == name) {
					plugin = p.second;
					break;
				}
			}
			if (m_tmplts[ifcIdx] != nullptr || (m_basic_idx >= 0 && g == BASIC_PLUGIN_NAME)) {
				throw PluginError("plugin can be specified only one time");
			}
			if (group.size() == 1 && g == BASIC_PLUGIN_NAME) {
				m_basic_idx = ifcIdx;
				break;
			}
			if (plugin == nullptr) {
				throw PluginError(g + " plugin is not activated");
			}
			pluginGroup.push_back(plugin);
		}

		// Create output template string and extension->ifc map
		std::string tmpltStr = basicTmplt;
		for (auto& p : pluginGroup) {
			RecordExt* ext = p->getExt();
			tmpltStr += std::string(",") + ext->getUnirecTmplt();
			int extId = ext->mExtId;
			delete ext;
			if (extId < 0) {
				continue;
			}
			if (m_ifc_map[extId] >= 0) {
				throw PluginError(
					"plugin output can be exported only to one interface at the moment");
			}
			m_ifc_map[extId] = ifcIdx;
		}

		createTmplt(ifcIdx, tmpltStr.c_str());
	}

	for (size_t i = 0; i < m_ifc_cnt; i++) { // Create unirec records.
		m_records[i] = ur_create_record(
			m_tmplts[i],
			(static_cast<ssize_t>(i) == m_basic_idx ? 0 : UR_MAX_SIZE));

		if (m_records[i] == nullptr) {
			freeUnirecResources();
			throw PluginError("not enough memory");
		}
	}

	m_group_map.clear();
}

void UnirecExporter::close()
{
	if (m_eof) {
		for (size_t i = 0; i < m_ifc_cnt; i++) {
			trap_send(i, "", 1);
		}
	}
	trap_finalize();
	freeUnirecResources();

	m_basic_idx = -1;
	m_ifc_cnt = 0;
	delete[] m_ext_id_flgs;
}

/**
 * \brief Free unirec templates and unirec records.
 */
void UnirecExporter::freeUnirecResources()
{
	if (m_tmplts) {
		for (size_t i = 0; i < m_ifc_cnt; i++) {
			if (m_tmplts[i] != nullptr) {
				ur_free_template(m_tmplts[i]);
			}
		}
		delete[] m_tmplts;
		m_tmplts = nullptr;
	}
	if (m_records) {
		for (size_t i = 0; i < m_ifc_cnt; i++) {
			if (m_records[i] != nullptr) {
				ur_free_record(m_records[i]);
			}
		}
		delete[] m_records;
		m_records = nullptr;
	}
	if (m_ifc_map) {
		delete[] m_ifc_map;
		m_ifc_map = nullptr;
	}
}

int UnirecExporter::exportFlow(const Flow& flow)
{
	RecordExt* ext = flow.mExts;
	ur_template_t* tmpltPtr = nullptr;
	void* recordPtr = nullptr;

	if (m_basic_idx >= 0) { // Process basic flow.
		tmpltPtr = m_tmplts[m_basic_idx];
		recordPtr = m_records[m_basic_idx];

		ur_clear_varlen(tmpltPtr, recordPtr);
		fillBasicFlow(flow, tmpltPtr, recordPtr);
		trap_send(
			m_basic_idx,
			recordPtr,
			ur_rec_fixlen_size(tmpltPtr) + ur_rec_varlen_size(tmpltPtr, recordPtr));
	}

	mFlowsSeen++;
	uint64_t tmpltDbits = 0; // templates dirty bits
	memset(
		m_ext_id_flgs,
		0,
		sizeof(int) * m_ext_cnt); // in case one flow has multiple extension of same type
	int extProcessedCnd = 0;
	while (ext != nullptr) {
		if (ext->mExtId >= static_cast<int>(m_ext_cnt)) {
			throw PluginError("encountered invalid extension id");
		}
		extProcessedCnd++;
		int ifcNum = m_ifc_map[ext->mExtId];
		if (ifcNum >= 0) {
			tmpltPtr = m_tmplts[ifcNum];
			recordPtr = m_records[ifcNum];

			if ((tmpltDbits & (1 << ifcNum)) == 0) {
				ur_clear_varlen(tmpltPtr, recordPtr);
				memset(recordPtr, 0, ur_rec_fixlen_size(tmpltPtr));
				tmpltDbits |= (1 << ifcNum);
			}

			if (m_ext_id_flgs[ext->mExtId] == 1) {
				// send the previously filled unirec record
				trap_send(ifcNum, recordPtr, ur_rec_size(tmpltPtr, recordPtr));
			} else {
				m_ext_id_flgs[ext->mExtId] = 1;
			}

			fillBasicFlow(flow, tmpltPtr, recordPtr);
			ext->fillUnirec(
				tmpltPtr,
				recordPtr); /* Add each extension header into unirec record. */
		}
		ext = ext->mNext;
	}
	// send the last record with all plugin data
	for (size_t ifcNum = 0; ifcNum < m_ifc_cnt && !(m_basic_idx >= 0) && extProcessedCnd > 0;
		 ifcNum++) {
		tmpltPtr = m_tmplts[ifcNum];
		recordPtr = m_records[ifcNum];
		trap_send(ifcNum, recordPtr, ur_rec_size(tmpltPtr, recordPtr));
	}
	return 0;
}

/**
 * \brief Fill record with basic flow fields.
 * \param [in] flow Flow record.
 * \param [in] tmplt_ptr Pointer to unirec template.
 * \param [out] record_ptr Pointer to unirec record.
 */
void UnirecExporter::fillBasicFlow(const Flow& flow, ur_template_t* tmpltPtr, void* recordPtr)
{
	ur_time_t tmpTime;

	if (flow.ipVersion == IP::V4) {
		ur_set(tmpltPtr, recordPtr, F_SRC_IP, ip_from_4_bytes_be((char*) &flow.srcIp.v4));
		ur_set(tmpltPtr, recordPtr, F_DST_IP, ip_from_4_bytes_be((char*) &flow.dstIp.v4));
	} else {
		ur_set(tmpltPtr, recordPtr, F_SRC_IP, ip_from_16_bytes_be((char*) flow.srcIp.v6));
		ur_set(tmpltPtr, recordPtr, F_DST_IP, ip_from_16_bytes_be((char*) flow.dstIp.v6));
	}

	tmpTime = ur_time_from_sec_usec(flow.timeFirst.tv_sec, flow.timeFirst.tv_usec);
	ur_set(tmpltPtr, recordPtr, F_TIME_FIRST, tmpTime);

	tmpTime = ur_time_from_sec_usec(flow.timeLast.tv_sec, flow.timeLast.tv_usec);
	ur_set(tmpltPtr, recordPtr, F_TIME_LAST, tmpTime);

	if (m_odid) {
		ur_set(tmpltPtr, recordPtr, F_ODID, m_link_bit_field);
	} else {
		ur_set(tmpltPtr, recordPtr, F_LINK_BIT_FIELD, m_link_bit_field);
	}
	ur_set(tmpltPtr, recordPtr, F_DIR_BIT_FIELD, m_dir_bit_field);
	ur_set(tmpltPtr, recordPtr, F_PROTOCOL, flow.ipProto);
	ur_set(tmpltPtr, recordPtr, F_SRC_PORT, flow.srcPort);
	ur_set(tmpltPtr, recordPtr, F_DST_PORT, flow.dstPort);
	ur_set(tmpltPtr, recordPtr, F_PACKETS, flow.srcPackets);
	ur_set(tmpltPtr, recordPtr, F_BYTES, flow.srcBytes);
	ur_set(tmpltPtr, recordPtr, F_TCP_FLAGS, flow.srcTcpFlags);
	ur_set(tmpltPtr, recordPtr, F_PACKETS_REV, flow.dstPackets);
	ur_set(tmpltPtr, recordPtr, F_BYTES_REV, flow.dstBytes);
	ur_set(tmpltPtr, recordPtr, F_TCP_FLAGS_REV, flow.dstTcpFlags);

	ur_set(tmpltPtr, recordPtr, F_DST_MAC, mac_from_bytes(const_cast<uint8_t*>(flow.dstMac)));
	ur_set(tmpltPtr, recordPtr, F_SRC_MAC, mac_from_bytes(const_cast<uint8_t*>(flow.srcMac)));
}

} // namespace ipxp
#endif
