/**
 * \file ntp.cpp
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
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdlib.h>

#ifdef WITH_NEMEA
#include <unirec/unirec.h>
#endif

#include "ntp.hpp"

namespace Ipxp {

int RecordExtNTP::s_registeredId = -1;

__attribute__((constructor)) static void registerThisPlugin()
{
	static PluginRecord rec = PluginRecord("ntp", []() { return new NTPPlugin(); });
	registerPlugin(&rec);
	RecordExtNTP::s_registeredId = registerExtension();
}

//#define DEBUG_NTP

/*Print debug message if debugging is allowed.*/
#ifdef DEBUG_NTP
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

NTPPlugin::NTPPlugin()
	: m_requests(0)
	, m_responses(0)
	, m_total(0)
{
}

NTPPlugin::~NTPPlugin()
{
	close();
}

void NTPPlugin::init(const char* params) {}

void NTPPlugin::close() {}

ProcessPlugin* NTPPlugin::copy()
{
	return new NTPPlugin(*this);
}

/**
 *\brief Called after a new flow record is created.
 *\param [in,out] rec Reference to flow record.
 *\param [in] pkt Parsed packet.
 *\return 0 on success or FLOW_FLUSH option.
 */
int NTPPlugin::postCreate(Flow& rec, const Packet& pkt)
{
	if (pkt.dstPort == 123 || pkt.srcPort == 123) {
		addExtNtp(rec, pkt);
		return FLOW_FLUSH;
	}

	return 0;
}

/**
 *\brief Called when everything is processed.
 */
void NTPPlugin::finish(bool printStats)
{
	if (printStats) {
		std::cout << "NTP plugin stats:" << std::endl;
		std::cout << "   Parsed NTP requests: " << m_requests << std::endl;
		std::cout << "   Parsed NTP responses: " << m_responses << std::endl;
		std::cout << "   Total NTP packets processed: " << m_total << std::endl;
	}
}

/**
 *\brief Add new extension NTP header into Flow.
 *\param [in] packet.
 *\param [out] rec Destination Flow.
 */
void NTPPlugin::addExtNtp(Flow& rec, const Packet& pkt)
{
	RecordExtNTP* ntpDataExt = new RecordExtNTP();
	if (!parseNtp(pkt, ntpDataExt)) {
		delete ntpDataExt; /*Don't add new extension packet.*/
	} else {
		rec.addExtension(ntpDataExt); /*Add extension to  packet.*/
	}
}

/**
 *\brief Parse and store NTP packet.
 *\param [in] Packet, and then take data Pointer to packet payload section.
 *\param [out] rec Output Flow extension header RecordExtNTP.
 *\return True if NTP was parsed.
 */
bool NTPPlugin::parseNtp(const Packet& pkt, RecordExtNTP* ntpDataExt)
{
	size_t i = 0;
	int number = 0, chCounter = 0;
	const unsigned char* payload = nullptr;
	unsigned char aux = '.';
	std::string result = "", result2 = "";
	std::string convert;
	std::string str;
	payload = (unsigned char*) pkt.payload;

	if (pkt.payloadLen == 0) {
		DEBUG_MSG("Parser quits:\tpayload length = 0\n");
		return false; /*Don't add extension to  paket.*/
	}

	try {
		DEBUG_MSG("\n---------- NTP PARSER #%u ----------\n", total + 1);

		/******************
		 * PARSE NTP_LEAP.*
		 * ****************/
		m_total++;
		aux = payload[0];
		aux = aux >> 6;
		ntpDataExt->leap = (uint8_t) aux;
		DEBUG_MSG("\tntp leap:\t\t%d\n", ntp_data_ext->leap);

		/*******************
		 *PARSE NTP_VERION.*
		 *******************/
		aux = payload[0];
		aux = aux << 2;
		aux = aux >> 5;
		ntpDataExt->version = (uint8_t) aux;
		if (ntpDataExt->version != 4) {
			throw "Error: Bad number of version or NTP exploit detected.";
		}
		DEBUG_MSG("\tntp version:\t\t%d\n", ntp_data_ext->version);

		/*****************
		 *PARSE NTP_MODE.*
		 *****************/
		aux = payload[0];
		aux = aux << 5;
		aux = aux >> 5;
		ntpDataExt->mode = (uint8_t) aux;
		if (ntpDataExt->mode < 3 || ntpDataExt->mode > 4) {
			throw "Error: Bad NTP mode or NTP exploit detected.";
		}
		if (ntpDataExt->mode == 3) {
			m_requests++;
		}
		if (ntpDataExt->mode == 4) {
			m_responses++;
		}
		DEBUG_MSG("\tntp mode:\t\t%d\n", ntp_data_ext->mode);

		/*********************
		 * PARSE NTP_STRATUM.*
		 * *******************/
		aux = payload[1];
		ntpDataExt->stratum = (uint8_t) aux;
		if (ntpDataExt->stratum > 16) {
			throw "Error: Bad NTP Stratum or NTP exploit detected.";
		}
		DEBUG_MSG("\tntp stratum:\t\t%d\n", ntp_data_ext->stratum);

		/*****************
		 * PARSE NTP_POLL.*
		 * ****************/
		aux = payload[2];
		ntpDataExt->poll = (uint8_t) aux;
		if (ntpDataExt->poll > 17) {
			throw "Error: Bad NTP Poll or NTP exploit detected.";
		}
		DEBUG_MSG("\tntp poll:\t\t%d\n", ntp_data_ext->poll);

		/*****************************************
		 * PARSE NTP_PRECISION         not used   *
		 ******************************************/
		aux = payload[3];
		ntpDataExt->precision = (uint8_t) aux;
		DEBUG_MSG("\tntp precision:\t\t%d\n", ntp_data_ext->precision);

		/******************************************
		 * PARSE NTP_DELAY-                        *
		 *payload [4][5][6][7]. not implemented yet*
		 *******************************************/

		/********************************************
		 * PARSE NTP_DISPERSION-                     *
		 *payload [8][9][10][11]. not implemented yet*
		 *********************************************/

		/**************************
		 * PARSE NTP_REF_ID -      *
		 *payload [12][13][14][15].*
		 ***************************/

		/********************************
		 * First octect NTP reference ID.*
		 * *******************************/
		chCounter = 0;
		number = (int) payload[12];
		convert = std::to_string(number);
		for (i = 0; i < convert.length(); i++) {
			ntpDataExt->referenceId[chCounter] = convert[i];
			chCounter++;
		}
		ntpDataExt->referenceId[chCounter] = '.';
		chCounter++;

		/*********************************
		 * Second octect NTP reference ID.*
		 * ********************************/
		number = (int) payload[13];
		convert = std::to_string(number);
		for (i = 0; i < convert.length(); i++) {
			ntpDataExt->referenceId[chCounter] = convert[i];
			chCounter++;
		}
		ntpDataExt->referenceId[chCounter] = '.';
		chCounter++;

		/********************************
		 * Third octect NTP reference ID.*
		 * *******************************/
		number = (int) payload[14];
		convert = std::to_string(number);
		for (i = 0; i < convert.length(); i++) {
			ntpDataExt->referenceId[chCounter] = convert[i];
			chCounter++;
		}
		ntpDataExt->referenceId[chCounter] = '.';
		chCounter++;

		/*********************************
		 * Fourth octect NTP reference ID.*
		 * ********************************/
		number = (int) payload[15];
		convert = std::to_string(number);
		for (i = 0; i < convert.length(); i++) {
			ntpDataExt->referenceId[chCounter] = convert[i];
			chCounter++;
		}
		ntpDataExt->referenceId[chCounter] = '\0';
		if (ntpDataExt->stratum == 0) {
			if (strcmp(ntpDataExt->referenceId, g_NTP_RefID_INIT) == 0) {
				strcpy(ntpDataExt->referenceId, g_INIT);
			}
			if (strcmp(ntpDataExt->referenceId, g_NTP_RefID_STEP) == 0) {
				strcpy(ntpDataExt->referenceId, g_STEP);
			}
			if (strcmp(ntpDataExt->referenceId, g_NTP_RefID_DENY) == 0) {
				strcpy(ntpDataExt->referenceId, g_DENY);
			}
			if (strcmp(ntpDataExt->referenceId, g_NTP_RefID_RATE) == 0) {
				strcpy(ntpDataExt->referenceId, g_RATE);
			}
		}
		DEBUG_MSG("\tntp reference id:\t\t%s\n", ntp_data_ext->reference_id);

		/*****************************
		 * PARSE NTP_REF -            *
		 * payload:                   *
		 * SECONDS   [16][17][18][19] *
		 * FRACTIONS [20][21][22][23].*
		 * ****************************/
		DEBUG_MSG("\tntp Reference Timestamp\n");
		chCounter = 0;
		result = parseTimestamp(pkt, 16, 19, 20, 23);
		for (i = 0; i < result.length(); i++) {
			ntpDataExt->reference[chCounter] = result[i];
			chCounter++;
		}
		ntpDataExt->reference[chCounter] = '\0';
		DEBUG_MSG("\t\ttimestamp:\t\t%s\n", ntp_data_ext->reference);

		/****************************
		 * PARSE NTP_ORIG -          *
		 *payload:                   *
		 *SECONDS   [24][25][26][27] *
		 *FRACTIONS [28][29][30][31].*
		 *****************************/
		DEBUG_MSG("\tntp Origin Timestamp\n");
		chCounter = 0;
		result = parseTimestamp(pkt, 24, 27, 28, 31);
		for (i = 0; i < result.length(); i++) {
			ntpDataExt->origin[chCounter] = result[i];
			chCounter++;
		}
		ntpDataExt->origin[chCounter] = '\0';
		DEBUG_MSG("\t\ttimestamp:\t\t%s\n", ntp_data_ext->origin);

		/****************************
		 * PARSE NTP_RECV -          *
		 *payload:                   *
		 *SECONDS   [32][33][34][35] *
		 *FRACTIONS [36][37][38][39].*
		 *****************************/
		DEBUG_MSG("\tntp Receive Timestamp\n");
		chCounter = 0;
		result = parseTimestamp(pkt, 32, 35, 36, 39);
		for (i = 0; i < result.length(); i++) {
			ntpDataExt->receive[chCounter] = result[i];
			chCounter++;
		}
		ntpDataExt->receive[chCounter] = '\0';
		DEBUG_MSG("\t\ttimestamp:\t\t%s\n", ntp_data_ext->receive);

		/****************************
		 * PARSE NTP_SENT -          *
		 *payload:                   *
		 *SECONDS   [40][41][42][43] *
		 *FRACTIONS [44][45][46][47].*
		 *****************************/
		DEBUG_MSG("\tntp Transmit Timestamp\n");
		chCounter = 0;
		result = parseTimestamp(pkt, 40, 43, 44, 47);
		for (i = 0; i < result.length(); i++) {
			ntpDataExt->sent[chCounter] = result[i];
			chCounter++;
		}
		ntpDataExt->sent[chCounter] = '\0';
		DEBUG_MSG("\t\ttimestamp:\t\t%s\n", ntp_data_ext->sent);

	} catch (const char* err) {
		DEBUG_MSG("%s\n", err);
		return false; /*Don't add extension to  paket.*/
	}

	return true; /*Add extension to  NTP packet*/
}

/**
 *\brief Parse of Timestamp NTP packet.
 *\param [in] Packet.
 *\param [in] P1: Index of Payload where the First octect of the Seconds timestamp.
 *\param [in] P4: Index of Payload where the Fourth octect of the Seconds timestamp.
 *\param [in] P5: Index of Payload where the First octect of the Fraction timestamp starts.
 *\param [in] P8: Index of Payload where the Fourth octect of the Fraction timestamp starts.
 *\return String of timestamp.
 */
std::string
NTPPlugin::parseTimestamp(const Packet& pkt, uint16_t p1, uint16_t p4, uint16_t p5, uint16_t p8)
{
	size_t i = 0, k = 0;
	int number = 0;
	const unsigned char* payload = nullptr;
	std::string result = "", result2 = "";
	std::string str;
	std::string convert2;
	std::string convert;
	char hexBuf[3];
	uint32_t time = 0;
	uint32_t highestbit = 0x80000000;
	double fract = 0.0f;
	uint32_t tmp = 0;
	double curfract = 0.5;
	payload = (unsigned char*) pkt.payload;

	/* ********************
	 * SECONDS CALCULATION.*
	 * *********************/
	result = "";
	number = 0;
	convert = "0";
	for (i = p1; i <= p4; i++) {
		number = payload[i];
		std::sprintf(hexBuf, "%x", number);
		convert += hexBuf;
	}
	result = convert;
	str = result;
	const char* c = str.c_str();
	time = strtoul(c, 0, 16);
	convert2 = std::to_string(time);
	DEBUG_MSG("\t\ttimestamp seconds:\t\t\t%u\n", time);

	/* *********************
	 * FRACTION CALCULATION.*
	 * **********************/
	result = "";
	convert2 += ".";
	convert = "";
	for (i = p5; i <= p8; i++) {
		number = payload[i];
		std::sprintf(hexBuf, "%x", number);
		convert += hexBuf;
	}
	result = convert;
	str = result;
	const char* c2 = str.c_str();
	time = strtoul(c2, 0, 16);
	tmp = time;
	for (i = 1; i <= 32; i++) {
		if ((highestbit & tmp) != 0) {
			fract = fract + curfract;
		}
		curfract = curfract / 2;
		tmp = tmp << 1;
	}
	DEBUG_MSG("\t\ttimestamp fraction:\t\t\t%f\n", fract);
	convert2 += std::to_string(fract);
	result2 = convert2;

	for (i = 0;; i++) {
		if (result2[i] == '.') {
			for (k = i + 2; k <= result2.length(); k++) {
				result2[k - 2] = result2[k];
			}
			break;
		}
	}
	result2.resize(result2.length() - 1);
	return result2;
}

} // namespace ipxp
