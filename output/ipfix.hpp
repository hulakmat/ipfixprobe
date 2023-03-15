/**
 * \file ipfix.hpp
 * \brief Export flows in IPFIX format.
 *    The following code was used https://dior.ics.muni.cz/~velan/flowmon-export-ipfix/
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2012 Masaryk University, Institute of Computer Science
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in
 * the documentation and/or other materials provided with the
 * distribution.
 * 3. Neither the name of the Masaryk University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
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
 */

#ifndef IPXP_OUTPUT_IPFIX_H
#define IPXP_OUTPUT_IPFIX_H

#include <map>
#include <vector>

#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/ipfix-elements.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/output.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/utils.hpp>

#define COUNT_IPFIX_TEMPLATES(T) +1

#define TEMPLATE_SET_ID 2
#define FIRST_TEMPLATE_ID 258
#define IPFIX_VERISON 10
#define DEFAULT_MTU 1458 /* 1500 - (ethernet 14 + ip 20 + udp 8) */
#define PACKET_DATA_SIZE DEFAULT_MTU
#define IPFIX_HEADER_SIZE 16
#define IPFIX_SET_HEADER_SIZE 4
#define TEMPLATE_BUFFER_SIZE (PACKET_DATA_SIZE - IPFIX_HEADER_SIZE)
#define TEMPLATE_FIELD_COUNT (0 IPFIX_ENABLED_TEMPLATES(COUNT_IPFIX_TEMPLATES))
#define TEMPLATE_RECORD_SIZE ((TEMPLATE_FIELD_COUNT) *8) // 2B eNum, 2B eID, 4B length
#define RECONNECT_TIMEOUT 60
#define TEMPLATE_REFRESH_TIME 600
#define TEMPLATE_REFRESH_PACKETS 0

namespace Ipxp {

class IpfixOptParser : public OptionsParser {
public:
	std::string mHost;
	uint16_t mPort;
	uint16_t mMtu;
	bool mUdp;
	uint64_t mId;
	uint32_t mDir;
	bool mVerbose;

	IpfixOptParser()
		: OptionsParser("ipfix", "Output plugin for ipfix export")
		, mHost("127.0.0.1")
		, mPort(4739)
		, mMtu(DEFAULT_MTU)
		, mUdp(false)
		, mId(DEFAULT_EXPORTER_ID)
		, mDir(0)
		, mVerbose(false)
	{
		registerOption(
			"h",
			"host",
			"ADDR",
			"Remote collector address",
			[this](const char* arg) {
				mHost = arg;
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"p",
			"port",
			"PORT",
			"Remote collector port",
			[this](const char* arg) {
				try {
					mPort = str2num<decltype(mPort)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"m",
			"mtu",
			"SIZE",
			"Maximum size of ipfix packet payload sent",
			[this](const char* arg) {
				try {
					mMtu = str2num<decltype(mMtu)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"u",
			"udp",
			"",
			"Use UDP protocol",
			[this](const char* arg) {
				mUdp = true;
				return true;
			},
			OptionFlags::NO_ARGUMENT);
		registerOption(
			"I",
			"id",
			"NUM",
			"Exporter identification",
			[this](const char* arg) {
				try {
					mId = str2num<decltype(mId)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"d",
			"dir",
			"NUM",
			"Dir bit field value",
			[this](const char* arg) {
				try {
					mDir = str2num<decltype(mDir)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"v",
			"verbose",
			"",
			"Enable verbose mode",
			[this](const char* arg) {
				mVerbose = true;
				return true;
			},
			OptionFlags::NO_ARGUMENT);
	}
};

typedef struct {
	char* name; /**< Record name */
	uint16_t enterpriseNumber; /**< Enterprise Number */
	uint16_t elementID; /**< Information Element ID */
	int32_t length; /**< Element export length. -1 for variable*/
} template_file_record_t;

/**
 * \brief Structure to hold template record
 */
typedef struct TemplateT {
	uint16_t id; /**< Template ID */
	uint8_t templateRecord[TEMPLATE_RECORD_SIZE]; /**< Buffer for template record */
	uint16_t templateSize; /**< Size of template record buffer */
	uint8_t* buffer; /**< Buffer with data for template */
	uint16_t bufferSize; /**< Size of data buffer */
	uint16_t recordCount; /**< Number of records in buffer */
	uint16_t fieldCount; /**< Number of elements in template */
	uint8_t exported; /**< 1 indicates that the template was exported to collector*/
	time_t exportTime; /**< Time when the template was last exported */
	uint64_t exportPacket; /**< Number of packet when the template was last exported */
	struct TemplateT* next;
} template_t;

/**
 * \brief Structure of ipfix packet used by send functions
 */
typedef struct {
	uint8_t* data; /**< Buffer for data */
	uint16_t length; /**< Length of data */
	uint16_t flows; /**< Number of flow records in the packet */
} ipfix_packet_t;

/**
 * \brief IPFIX header structure
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |       Version Number          |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           Export Time                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                       Sequence Number                         |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Observation Domain ID                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef struct IpfixHeader {
	/**
	 * Version of Flow Record format exported in this message. The value of this
	 * field is 0x000a for the current version, incrementing by one the version
	 * used in the NetFlow services export version 9.
	 */
	uint16_t version;

	/**
	 * Total length of the IPFIX Message, measured in octets, including Message
	 * Header and Set(s).
	 */
	uint16_t length;

	/**
	 * Time, in seconds, since 0000 UTC Jan 1, 1970, at which the IPFIX Message
	 * Header leaves the Exporter.
	 */
	uint32_t exportTime;

	/**
	 * Incremental sequence counter modulo 2^32 of all IPFIX Data Records sent
	 * on this PR-SCTP stream from the current Observation Domain by the
	 * Exporting Process. Check the specific meaning of this field in the
	 * subsections of Section 10 when UDP or TCP is selected as the transport
	 * protocol. This value SHOULD be used by the Collecting Process to
	 * identify whether any IPFIX Data Records have been missed. Template and
	 * Options Template Records do not increase the Sequence Number.
	 */
	uint32_t sequenceNumber;

	/**
	 * A 32-bit identifier of the Observation Domain that is locally unique to
	 * the Exporting Process. The Exporting Process uses the Observation Domain
	 * ID to uniquely identify to the Collecting Process the Observation Domain
	 * that metered the Flows. It is RECOMMENDED that this identifier also be
	 * unique per IPFIX Device. Collecting Processes SHOULD use the Transport
	 * Session and the Observation Domain ID field to separate different export
	 * streams originating from the same Exporting Process. The Observation
	 * Domain ID SHOULD be 0 when no specific Observation Domain ID is relevant
	 * for the entire IPFIX Message, for example, when exporting the Exporting
	 * Process Statistics, or in case of a hierarchy of Collectors when
	 * aggregated Data Records are exported.
	 */
	uint32_t observationDomainId;
} ipfix_header_t;

/**
 * \brief Common IPFIX Set (header) structure
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Set ID               |          Length               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
typedef struct IpfixTemplateSetHeader {
	/**
	 * Set ID value identifies the Set.  A value of 2 is reserved for the
	 * Template Set. A value of 3 is reserved for the Option Template Set. All
	 * other values from 4 to 255 are reserved for future use. Values above 255
	 * are used for Data Sets. The Set ID values of 0 and 1 are not used for
	 * historical reasons [<a href="http://tools.ietf.org/html/rfc3954">RFC3954</a>].
	 */
	uint16_t id;

	/**
	 * Total length of the Set, in octets, including the Set Header, all
	 * records, and the optional padding.  Because an individual Set MAY contain
	 * multiple records, the Length value MUST be used to determine the position
	 * of the next Set.
	 */
	uint16_t length;

} ipfix_template_set_header_t;

class IPFIXExporter : public OutputPlugin {
public:
	IPFIXExporter();
	~IPFIXExporter();
	void init(const char* params);
	void init(const char* params, Plugins& plugins);
	void close();
	OptionsParser* getParser() const { return new IpfixOptParser(); }
	std::string getName() const { return "ipfix"; }
	int exportFlow(const Flow& flow);

private:
	/* Templates */
	enum TmpltMapIdx { TMPLT_IDX_V4 = 0, TMPLT_IDX_V6 = 1, TMPLT_MAP_IDX_CNT };
	RecordExt** m_extensions;
	int m_extension_cnt;
	std::map<uint64_t, template_t*> m_tmpltMap[TMPLT_MAP_IDX_CNT];
	template_t* m_templates; /**< Templates in use by plugin */
	uint16_t m_templatesDataSize; /**< Total data size stored in templates */
	int m_basic_ifc_num;
	bool m_verbose;

	uint32_t m_sequenceNum; /**< Number of exported flows */
	uint64_t m_exportedPackets; /**< Number of exported packets */
	int m_fd; /**< Socket used to send data */
	struct addrinfo* m_addrinfo; /**< Info about the connection used by sendto */

	/* Parameters */
	std::string m_host; /**< Collector address */
	uint16_t m_port; /**< Collector port */
	int m_protocol; /**< Collector connection protocol */
	int m_ip; /**< IP protocol version (AF_INET, ...) */
	int m_flags; /**< getaddrinfo flags */

	uint32_t m_reconnectTimeout; /**< Timeout between connection retries */
	time_t m_lastReconnect; /**< Time in seconds of last connection retry */
	uint32_t m_odid; /**< Observation Domain ID */
	uint32_t m_templateRefreshTime; /**< UDP template refresh time interval */
	uint32_t m_templateRefreshPackets; /**< UDP template refresh packet interval */
	uint32_t m_dir_bit_field; /**< Direction bit field value. */

	uint16_t m_mtu; /**< Max size of packet payload sent */
	uint8_t* m_packetDataBuffer; /**< Data buffer to store packet */
	uint16_t m_tmpltMaxBufferSize; /**< Size of template buffer, tmpltBufferSize < packetDataBuffer */

	void initTemplateBuffer(template_t* tmpl);
	int fillTemplateSetHeader(uint8_t* ptr, uint16_t size);
	void checkTemplateLifetime(template_t* tmpl);
	int fillIpfixHeader(uint8_t* ptr, uint16_t size);
	template_file_record_t* getTemplateRecordByName(const char* name);
	void expireTemplates();
	template_t* createTemplate(const char** tmplt, const char** ext);
	uint16_t createTemplatePacket(ipfix_packet_t* packet);
	uint16_t createDataPacket(ipfix_packet_t* packet);
	void sendTemplates();
	void sendData();
	int sendPacket(ipfix_packet_t* packet);
	int connectToCollector();
	int reconnect();
	int fillBasicFlow(const Flow& flow, template_t* tmplt);
	int fillExtensions(RecordExt* ext, uint8_t* buffer, int size);

	uint64_t getTemplateId(const Record& flow);
	template_t* getTemplate(const Flow& flow);
	bool fillTemplate(const Flow& flow, template_t* tmplt);
	void flush();
	void shutdown();
};

} // namespace ipxp
#endif /* IPXP_OUTPUT_IPFIX_HPP */
