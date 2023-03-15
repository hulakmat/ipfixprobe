/**
 * \file flowifc.hpp
 * \brief Structs/classes for communication between flow cache and exporter
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

#ifndef IPXP_FLOWIFC_HPP
#define IPXP_FLOWIFC_HPP

/* Interface between flow cache and flow exporter. */

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/time.h>

#ifdef WITH_NEMEA
#include "fields.h"
#include <unirec/unirec.h>
#else
#define UR_FIELDS(...)
#endif

#include "ipaddr.hpp"
#include <arpa/inet.h>

namespace Ipxp {

#define BASIC_PLUGIN_NAME "basic"

int registerExtension();
int getExtensionCnt();

/**
 * \brief Flow record extension base struct.
 */
struct RecordExt {
	RecordExt* mNext; /**< Pointer to next extension */
	int mExtId; /**< Identifier of extension. */

	/**
	 * \brief Constructor.
	 * \param [in] id ID of extension.
	 */
	RecordExt(int id)
		: mNext(nullptr)
		, mExtId(id)
	{
	}

#ifdef WITH_NEMEA
	/**
	 * \brief Fill unirec record with stored extension data.
	 * \param [in] tmplt Unirec template.
	 * \param [out] record Pointer to the unirec record.
	 */
	virtual void fillUnirec(ur_template_t* tmplt, void* record) {}

	/**
	 * \brief Get unirec template string.
	 * \return Unirec template string.
	 */
	virtual const char* getUnirecTmplt() const
	{
		return "";
	}
#endif

	/**
	 * \brief Fill IPFIX record with stored extension data.
	 * \param [out] buffer IPFIX template record buffer.
	 * \param [in] size IPFIX template record buffer size.
	 * \return Number of bytes written to buffer or -1 if data cannot be written.
	 */
	virtual int fillIpfix(uint8_t* buffer, int size)
	{
		return 0;
	}

	/**
	 * \brief Get ipfix string fields.
	 * \return Return ipfix fields array.
	 */
	virtual const char** getIpfixTmplt() const
	{
		return nullptr;
	}

	/**
	 * \brief Get text representation of exported elements
	 * \return Return fields converted to text
	 */
	virtual std::string getText() const
	{
		return "";
	}

	/**
	 * \brief Add extension at the end of linked list.
	 * \param [in] ext Extension to add.
	 */
	void addExtension(RecordExt* ext)
	{
		RecordExt** tmp = &mNext;
		while (*tmp) {
			tmp = &(*tmp)->mNext;
		}
		*tmp = ext;
	}

	/**
	 * \brief Virtual destructor.
	 */
	virtual ~RecordExt()
	{
		if (mNext != nullptr) {
			delete mNext;
		}
	}
};

struct Record {
	RecordExt* mExts; /**< Extension headers. */

	/**
	 * \brief Add new extension header.
	 * \param [in] ext Pointer to the extension header.
	 */
	void addExtension(RecordExt* ext)
	{
		if (mExts == nullptr) {
			mExts = ext;
		} else {
			RecordExt* extPtr = mExts;
			while (extPtr->mNext != nullptr) {
				extPtr = extPtr->mNext;
			}
			extPtr->mNext = ext;
		}
	}

	/**
	 * \brief Get given extension.
	 * \param [in] id Type of extension.
	 * \return Pointer to the requested extension or nullptr if extension is not present.
	 */
	RecordExt* getExtension(int id) const
	{
		RecordExt* ext = mExts;
		while (ext != nullptr) {
			if (ext->mExtId == id) {
				return ext;
			}
			ext = ext->mNext;
		}
		return nullptr;
	}
	/**
	 * \brief Remove given extension.
	 * \param [in] id Type of extension.
	 * \return True when successfully removed
	 */
	bool removeExtension(int id)
	{
		RecordExt* ext = mExts;
		RecordExt* prevExt = nullptr;

		while (ext != nullptr) {
			if (ext->mExtId == id) {
				if (prevExt == nullptr) { // at beginning
					mExts = ext->mNext;
				} else if (ext->mNext == nullptr) { // at end
					prevExt->mNext = nullptr;
				} else { // in middle
					prevExt->mNext = ext->mNext;
				}
				ext->mNext = nullptr;
				delete ext;
				return true;
			}
			prevExt = ext;
			ext = ext->mNext;
		}
		return false;
	}

	/**
	 * \brief Remove extension headers.
	 */
	void removeExtensions()
	{
		if (mExts != nullptr) {
			delete mExts;
			mExts = nullptr;
		}
	}

	/**
	 * \brief Constructor.
	 */
	Record()
		: mExts(nullptr)
	{
	}

	/**
	 * \brief Destructor.
	 */
	virtual ~Record() { removeExtensions(); }
};

#define FLOW_END_INACTIVE 0x01
#define FLOW_END_ACTIVE 0x02
#define FLOW_END_EOF 0x03
#define FLOW_END_FORCED 0x04
#define FLOW_END_NO_RES 0x05

/**
 * \brief Flow record struct constaining basic flow record data and extension headers.
 */
struct Flow : public Record {
	struct timeval timeFirst;
	struct timeval timeLast;
	uint64_t srcBytes;
	uint64_t dstBytes;
	uint32_t srcPackets;
	uint32_t dstPackets;
	uint8_t srcTcpFlags;
	uint8_t dstTcpFlags;

	uint8_t ipVersion;

	uint8_t ipProto;
	uint16_t srcPort;
	uint16_t dstPort;
	ipaddr_t srcIp;
	ipaddr_t dstIp;

	uint8_t srcMac[6];
	uint8_t dstMac[6];
	uint8_t endReason;
};

} // namespace ipxp
#endif /* IPXP_FLOWIFC_HPP */
