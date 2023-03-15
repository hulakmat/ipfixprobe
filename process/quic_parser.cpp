/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022, CESNET z.s.p.o.
 */

/**
 * \file quic_parser.cpp
 * \brief Class for parsing quic traffic.
 * \author Andrej Lukacovic lukacan1@fit.cvut.cz
 * \author Karel Hynek <Karel.Hynek@cesnet.cz>
 * \date 2022
 */

#include "quic_parser.hpp"

// #include "quic_variable_length.cpp"

#ifdef DEBUG_QUIC
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_QUIC
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

namespace Ipxp {
QUICParser::QUICParser()
{
	m_quic_h1 = nullptr;
	m_quic_h2 = nullptr;
	m_payload = nullptr;

	m_header_len = 0;
	m_payload_len = 0;

	m_dcid = nullptr;
	m_pkn = nullptr;
	m_sample = nullptr;
	m_salt = nullptr;
	m_final_payload = nullptr;
	m_parsed_initial = 0;
	m_is_version2 = false;
}

void QUICParser::quicGetVersion(uint32_t& versionToset)
{
	versionToset = m_version;
	return;
}

void QUICParser::quicGetSni(char* in)
{
	memcpy(in, m_sni, BUFF_SIZE);
	return;
}

void QUICParser::quicGetUserAgent(char* in)
{
	memcpy(in, m_user_agent, BUFF_SIZE);
	return;
}

bool QUICParser::quicCheckPointerPos(const uint8_t* current, const uint8_t* end)
{
	if (current < end)
		return true;

	return false;
}

uint64_t QUICParser::quicGetVariableLength(const uint8_t* start, uint64_t& offset)
{
	// find out length of parameter field (and load parameter, then move offset) , defined in:
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-summary-of-integer-encoding
	// this approach is used also in length field , and other QUIC defined fields.
	uint64_t tmp = 0;

	uint8_t twoBits = *(start + offset) & 0xC0;

	switch (twoBits) {
	case 0:
		tmp = *(start + offset) & 0x3F;
		offset += sizeof(uint8_t);
		return tmp;
	case 64:
		tmp = be16toh(*(uint16_t*) (start + offset)) & 0x3FFF;
		offset += sizeof(uint16_t);
		return tmp;
	case 128:
		tmp = be32toh(*(uint32_t*) (start + offset)) & 0x3FFFFFFF;
		offset += sizeof(uint32_t);
		return tmp;
	case 192:
		tmp = be64toh(*(uint64_t*) (start + offset)) & 0x3FFFFFFFFFFFFFFF;
		offset += sizeof(uint64_t);
		return tmp;
	default:
		return 0;
	}
} // QUICParser::quic_get_variable_length

bool QUICParser::quicObtainTlsData(TLSData& payload)
{
	while (payload.start + sizeof(TlsExt) <= payload.end) {
		TlsExt* ext = (TlsExt*) payload.start;
		uint16_t type = ntohs(ext->type);
		uint16_t length = ntohs(ext->length);

		payload.start += sizeof(TlsExt);

		if (payload.start + length > payload.end) {
			break;
		}

		if (type == TLS_EXT_SERVER_NAME && length != 0) {
			m_tls_parser.tlsGetServerName(payload, m_sni, BUFF_SIZE);
		} else if (
			(type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V1
			 || type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS
			 || type == TLS_EXT_QUIC_TRANSPORT_PARAMETERS_V2)
			&& length != 0) {
			m_tls_parser.tlsGetQuicUserAgent(payload, m_user_agent, BUFF_SIZE);
		}
		payload.start += length;
	}
	return payload.obejctsParsed != 0;
}

bool QUICParser::quicParseTls()
{
	TLSData payload = {
		payload.start = m_final_payload + m_quic_crypto_start,
		payload.end = m_final_payload + m_quic_crypto_start + m_quic_crypto_len,
		payload.obejctsParsed = 0,
	};

	if (!m_tls_parser.tlsCheckHandshake(payload)) {
		return false;
	}
	if (!m_tls_parser.tlsSkipRandom(payload)) {
		return false;
	}
	if (!m_tls_parser.tlsSkipSessid(payload)) {
		return false;
	}
	if (!m_tls_parser.tlsSkipCipherSuites(payload)) {
		return false;
	}
	if (!m_tls_parser.tlsSkipCompressionMet(payload)) {
		return false;
	}
	if (!m_tls_parser.tlsCheckExtLen(payload)) {
		return false;
	}
	if (!quicObtainTlsData(payload)) {
		return false;
	}
	return true;
} // QUICPlugin::quic_parse_tls

uint8_t QUICParser::quicDraftVersion(uint32_t version)
{
	// this is IETF implementation, older version used
	if ((version >> 8) == OLDER_VERSION) {
		return (uint8_t) version;
	}
	switch (version) {
	// older mvfst version, but still used, based on draft 22, but salt 21 used
	case (FACEEBOOK1):
		return 22;
	// more used atm, salt 23 used
	case FACEEBOOK2:
	case FACEBOOK_EXPERIMENTAL:
		return 27;
	case (FORCE_VER_NEG_PATTERN & 0x0F0F0F0F):
		return 29;

	// version 2 draft 00
	case Q_VERSION2_DRAFT00:
	// newest
	case Q_VERSION2_NEWEST:
		return 100;

	default:
		return 255;
	}
}

bool QUICParser::quicCheckVersion(uint32_t version, uint8_t maxVersion)
{
	uint8_t draftVersion = quicDraftVersion(version);

	return draftVersion && draftVersion <= maxVersion;
}

bool QUICParser::quicObtainVersion()
{
	m_version = m_quic_h1->version;
	m_version = ntohl(m_version);
	// this salt is used to draft 7-9
	static const uint8_t handshakeSaltDraft7[SALT_LENGTH]
		= {0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e, 0xca, 0x1e, 0x9d,
		   0x36, 0xf3, 0x7f, 0xb2, 0xd4, 0x65, 0x18, 0xc3, 0x66, 0x39};
	// this salt is used to draft 10-16
	static const uint8_t handshakeSaltDraft10[SALT_LENGTH]
		= {0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
		   0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38};
	// this salt is used to draft 17-20
	static const uint8_t handshakeSaltDraft17[SALT_LENGTH]
		= {0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef,
		   0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0};
	// this salt is used to draft 21-22
	static const uint8_t handshakeSaltDraft21[SALT_LENGTH]
		= {0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
		   0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a};
	// this salt is used to draft 23-28
	static const uint8_t handshakeSaltDraft23[SALT_LENGTH] = {
		0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
		0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02,
	};
	// this salt is used to draft 29-32
	static const uint8_t handshakeSaltDraft29[SALT_LENGTH]
		= {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		   0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};
	// newest 33 -
	static const uint8_t handshakeSaltV1[SALT_LENGTH]
		= {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		   0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
	static const uint8_t handshakeSaltV2[SALT_LENGTH]
		= {0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18, 0x4a, 0x1d,
		   0x62, 0xca, 0x57, 0x04, 0x06, 0xea, 0x7a, 0xe3, 0xe5, 0xd3};

	if (m_version == VERSION_NEGOTIATION) {
		DEBUG_MSG("Error, version negotiation\n");
		return false;
	} else if (!m_is_version2 && m_version == QUIC_NEWEST) {
		m_salt = handshakeSaltV1;
	} else if (!m_is_version2 && quicCheckVersion(m_version, 9)) {
		m_salt = handshakeSaltDraft7;
	} else if (!m_is_version2 && quicCheckVersion(m_version, 16)) {
		m_salt = handshakeSaltDraft10;
	} else if (!m_is_version2 && quicCheckVersion(m_version, 20)) {
		m_salt = handshakeSaltDraft17;
	} else if (!m_is_version2 && quicCheckVersion(m_version, 22)) {
		m_salt = handshakeSaltDraft21;
	} else if (!m_is_version2 && quicCheckVersion(m_version, 28)) {
		m_salt = handshakeSaltDraft23;
	} else if (!m_is_version2 && quicCheckVersion(m_version, 32)) {
		m_salt = handshakeSaltDraft29;
	} else if (m_is_version2 && quicCheckVersion(m_version, 100)) {
		m_salt = handshakeSaltV2;
	} else {
		DEBUG_MSG("Error, version not supported\n");
		return false;
	}

	return true;
} // QUICParser::quic_obtain_version

bool expandLabel(
	const char* labelPrefix,
	const char* label,
	const uint8_t* contextHash,
	uint8_t contextLength,
	uint16_t desiredLen,
	uint8_t* out,
	uint8_t& outLen)
{
	/* HKDF-Expand-Label(Secret, Label, Context, Length) =
	 *      HKDF-Expand(Secret, HkdfLabel, Length)
	 *
	 * Where HkdfLabel is specified as:
	 *
	 * struct {
	 *     uint16 length = Length;
	 *     opaque label<7..255> = "tls13 " + Label;
	 *     opaque context<0..255> = Context;
	 * } HkdfLabel;
	 *
	 *
	 * https://datatracker.ietf.org/doc/html/rfc8446#section-3.4
	 * "... the actual length precedes the vector's contents in the byte stream ... "
	 * */

	const unsigned int labelPrefixLength = (unsigned int) strlen(labelPrefix);
	const unsigned int labelLength = (unsigned int) strlen(label);

	const uint8_t labelVectorLength = labelPrefixLength + labelLength;
	const uint16_t length = ntohs(desiredLen);

	outLen = sizeof(length) + sizeof(labelVectorLength) + labelVectorLength
		+ sizeof(contextLength);

	// copy length
	memcpy(out, &length, sizeof(length));
	// copy whole label length as described above
	memcpy(out + sizeof(length), &labelVectorLength, sizeof(labelVectorLength));
	// copy label prefix ("tls13 ")
	memcpy(out + sizeof(length) + sizeof(labelVectorLength), labelPrefix, labelPrefixLength);
	// copy actual label
	memcpy(
		out + sizeof(length) + sizeof(labelVectorLength) + labelPrefixLength,
		label,
		labelLength);
	// copy context length (should be 0)
	memcpy(
		out + sizeof(length) + sizeof(labelVectorLength) + labelPrefixLength + labelLength,
		&contextLength,
		sizeof(contextLength));
	return true;
}

bool quicDeriveNSet(
	uint8_t* secret,
	uint8_t* expandedLabel,
	uint8_t size,
	size_t outputLen,
	uint8_t* storeData)
{
	EVP_PKEY_CTX* pctx;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (1 != EVP_PKEY_derive_init(pctx)) {
		DEBUG_MSG("Error, context initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
		DEBUG_MSG("Error, mode initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) {
		DEBUG_MSG("Error, message digest initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, expandedLabel, size)) {
		DEBUG_MSG("Error, info initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, HASH_SHA2_256_LENGTH)) {
		DEBUG_MSG("Error, key initialization failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_derive(pctx, storeData, &outputLen)) {
		DEBUG_MSG("Error, HKDF-Expand derivation failed %s\n", (char*) expanded_label);
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	EVP_PKEY_CTX_free(pctx);
	return true;
} // QUICPlugin::quic_derive_n_set

bool QUICParser::quicDeriveSecrets(uint8_t* secret)
{
	uint8_t lenQuicKey;
	uint8_t lenQuicIv;
	uint8_t lenQuicHp;

	// expand label for other initial secrets
	if (!m_is_version2) {
		uint8_t quicKey[QUIC_KEY_HKDF_V1] = {0};
		uint8_t quicIv[QUIC_IV_HKDF_V1] = {0};
		uint8_t quicHp[QUIC_HP_HKDF_V1] = {0};
		expandLabel("tls13 ", "quic key", NULL, 0, AES_128_KEY_LENGTH, quicKey, lenQuicKey);
		expandLabel("tls13 ", "quic iv", NULL, 0, TLS13_AEAD_NONCE_LENGTH, quicIv, lenQuicIv);
		expandLabel("tls13 ", "quic hp", NULL, 0, AES_128_KEY_LENGTH, quicHp, lenQuicHp);
		// use HKDF-Expand to derive other secrets
		if (!quicDeriveNSet(
				secret,
				quicKey,
				lenQuicKey,
				AES_128_KEY_LENGTH,
				m_initial_secrets.key)
			|| !quicDeriveNSet(
				secret,
				quicIv,
				lenQuicIv,
				TLS13_AEAD_NONCE_LENGTH,
				m_initial_secrets.iv)
			|| !quicDeriveNSet(
				secret,
				quicHp,
				lenQuicHp,
				AES_128_KEY_LENGTH,
				m_initial_secrets.hp)) {
			DEBUG_MSG("Error, derivation of initial secrets failed\n");
			return false;
		}
	} else {
		uint8_t quicKey[QUIC_KEY_HKDF_V2] = {0};
		uint8_t quicIv[QUIC_IV_HKDF_V2] = {0};
		uint8_t quicHp[QUIC_HP_HKDF_V2] = {0};
		expandLabel("tls13 ", "quicv2 key", NULL, 0, AES_128_KEY_LENGTH, quicKey, lenQuicKey);
		expandLabel("tls13 ", "quicv2 iv", NULL, 0, TLS13_AEAD_NONCE_LENGTH, quicIv, lenQuicIv);
		expandLabel("tls13 ", "quicv2 hp", NULL, 0, AES_128_KEY_LENGTH, quicHp, lenQuicHp);

		// use HKDF-Expand to derive other secrets
		if (!quicDeriveNSet(
				secret,
				quicKey,
				lenQuicKey,
				AES_128_KEY_LENGTH,
				m_initial_secrets.key)
			|| !quicDeriveNSet(
				secret,
				quicIv,
				lenQuicIv,
				TLS13_AEAD_NONCE_LENGTH,
				m_initial_secrets.iv)
			|| !quicDeriveNSet(
				secret,
				quicHp,
				lenQuicHp,
				AES_128_KEY_LENGTH,
				m_initial_secrets.hp)) {
			DEBUG_MSG("Error, derivation of initial secrets failed\n");
			return false;
		}
	}

	return true;
} // QUICPlugin::quic_derive_secrets

bool QUICParser::quicCreateInitialSecrets()
{
	uint8_t extractedSecret[HASH_SHA2_256_LENGTH] = {0};
	size_t extrLen = HASH_SHA2_256_LENGTH;

	uint8_t expandedSecret[HASH_SHA2_256_LENGTH] = {0};
	size_t expdLen = HASH_SHA2_256_LENGTH;

	uint8_t expandLabelBuffer[QUIC_CLIENTIN_HKDF];
	uint8_t expandLabelLen;

	// HKDF-Extract
	EVP_PKEY_CTX* pctx;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (1 != EVP_PKEY_derive_init(pctx)) {
		DEBUG_MSG("Error, context initialization failed(Extract)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)) {
		DEBUG_MSG("Error, mode initialization failed(Extract)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) {
		DEBUG_MSG("Error, message digest initialization failed(Extract)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx, m_salt, SALT_LENGTH)) {
		DEBUG_MSG("Error, salt initialization failed(Extract)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, m_dcid, m_quic_h1->dcidLen)) {
		DEBUG_MSG("Error, key initialization failed(Extract)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_derive(pctx, extractedSecret, &extrLen)) {
		DEBUG_MSG("Error, HKDF-Extract derivation failed\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	// Expand-Label
	expandLabel(
		"tls13 ",
		"client in",
		NULL,
		0,
		HASH_SHA2_256_LENGTH,
		expandLabelBuffer,
		expandLabelLen);
	// HKDF-Expand
	if (!EVP_PKEY_derive_init(pctx)) {
		DEBUG_MSG("Error, context initialization failed(Expand)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)) {
		DEBUG_MSG("Error, mode initialization failed(Expand)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) {
		DEBUG_MSG("Error, message digest initialization failed(Expand)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, expandLabelBuffer, expandLabelLen)) {
		DEBUG_MSG("Error, info initialization failed(Expand)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, extractedSecret, HASH_SHA2_256_LENGTH)) {
		DEBUG_MSG("Error, key initialization failed(Expand)\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	if (1 != EVP_PKEY_derive(pctx, expandedSecret, &expdLen)) {
		DEBUG_MSG("Error, HKDF-Expand derivation failed\n");
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	EVP_PKEY_CTX_free(pctx);
	if (!quicDeriveSecrets(expandedSecret)) {
		DEBUG_MSG("Error, Derivation of initial secrets failed\n");
		return false;
	}
	return true;
} // QUICPlugin::quic_create_initial_secrets

bool QUICParser::quicEncryptSample(uint8_t* plaintext)
{
	int len = 0;
	EVP_CIPHER_CTX* ctx;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		DEBUG_MSG("Sample encryption, creating context failed\n");
		return false;
	}
	if (!(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, m_initial_secrets.hp, NULL))) {
		DEBUG_MSG("Sample encryption, context initialization failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	// we need to disable padding so we can use EncryptFinal
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	if (!(EVP_EncryptUpdate(ctx, plaintext, &len, m_sample, SAMPLE_LENGTH))) {
		DEBUG_MSG("Sample encryption, decrypting header failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	if (!(EVP_EncryptFinal_ex(ctx, plaintext + len, &len))) {
		DEBUG_MSG("Sample encryption, final header decryption failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	EVP_CIPHER_CTX_free(ctx);
	return true;
}

bool QUICParser::quicDecryptHeader(const Packet& pkt)
{
	uint8_t plaintext[SAMPLE_LENGTH];
	uint8_t mask[5] = {0};
	uint8_t fullPkn[4] = {0};
	uint8_t firstByte = 0;
	uint32_t packetNumber = 0;
	uint8_t pknLen;

	// https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection-applicati

	/*
	 * mask = header_protection(hp_key, sample)
	 *
	 * pn_length = (packet[0] & 0x03) + 1
	 *
	 * if (packet[0] & 0x80) == 0x80:
	 # Long header: 4 bits masked
	 #    packet[0] ^= mask[0] & 0x0f
	 # else:
	 # Short header: 5 bits masked
	 #    packet[0] ^= mask[0] & 0x1f
	 */

	// Encrypt sample with AES-ECB. Encrypted sample is used in XOR with packet header
	if (!quicEncryptSample(plaintext)) {
		return false;
	}
	memcpy(mask, plaintext, sizeof(mask));

	firstByte = m_quic_h1->firstByte ^ (mask[0] & 0x0f);
	pknLen = (firstByte & 0x03) + 1;

	// after de-obfuscating pkn, we know exactly pkn length so we can correctly adjust start of
	// payload
	m_payload = m_payload + pknLen;
	m_payload_len = m_payload_len - pknLen;
	m_header_len = m_payload - pkt.payload;
	if (m_header_len > MAX_HEADER_LEN) {
		DEBUG_MSG("Header length too long\n");
		return false;
	}

	memcpy(m_tmp_header_mem, pkt.payload, m_header_len);
	m_header = m_tmp_header_mem;

	m_header[0] = firstByte;

	memcpy(&fullPkn, m_pkn, pknLen);
	for (unsigned int i = 0; i < pknLen; i++) {
		packetNumber |= (fullPkn[i] ^ mask[1 + i]) << (8 * (pknLen - 1 - i));
	}
	for (unsigned i = 0; i < pknLen; i++) {
		m_header[m_header_len - 1 - i] = (uint8_t) (packetNumber >> (8 * i));
	}
	// adjust nonce for payload decryption
	// https://www.rfc-editor.org/rfc/rfc9001.html#name-aead-usage
	//  The exclusive OR of the padded packet number and the IV forms the AEAD nonce
	phton64(
		m_initial_secrets.iv + sizeof(m_initial_secrets.iv) - 8,
		pntoh64(m_initial_secrets.iv + sizeof(m_initial_secrets.iv) - 8) ^ packetNumber);
	return true;
} // QUICPlugin::quic_decrypt_header

bool QUICParser::quicDecryptPayload()
{
	uint8_t atag[16] = {0};
	int len;

	/* Input is --> "header || ciphertext (buffer) || auth tag (16 bytes)" */

	if (m_payload_len <= 16) {
		DEBUG_MSG("Payload decryption error, ciphertext too short\n");
		return false;
	}
	// https://datatracker.ietf.org/doc/html/draft-ietf-quic-tls-34#section-5.3
	// "These cipher suites have a 16-byte authentication tag and produce an output 16 bytes larger
	// than their input." adjust length because last 16 bytes are authentication tag
	m_payload_len -= 16;
	memcpy(&atag, &m_payload[m_payload_len], 16);
	EVP_CIPHER_CTX* ctx;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		DEBUG_MSG("Payload decryption error, creating context failed\n");
		return false;
	}
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
		DEBUG_MSG("Payload decryption error, context initialization failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, TLS13_AEAD_NONCE_LENGTH, NULL)) {
		DEBUG_MSG("Payload decryption error, setting NONCE length failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	// SET NONCE and KEY
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, m_initial_secrets.key, m_initial_secrets.iv)) {
		DEBUG_MSG("Payload decryption error, setting KEY and NONCE failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	// SET ASSOCIATED DATA (HEADER with unprotected PKN)
	if (!EVP_DecryptUpdate(ctx, NULL, &len, m_header, m_header_len)) {
		DEBUG_MSG("Payload decryption error, initializing authenticated data failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	if (!EVP_DecryptUpdate(ctx, m_decrypted_payload, &len, m_payload, m_payload_len)) {
		DEBUG_MSG("Payload decryption error, decrypting payload failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, atag)) {
		DEBUG_MSG("Payload decryption error, TAG check failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	if (!EVP_DecryptFinal_ex(ctx, m_decrypted_payload + len, &len)) {
		DEBUG_MSG("Payload decryption error, final payload decryption failed\n");
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	EVP_CIPHER_CTX_free(ctx);
	m_final_payload = m_decrypted_payload;
	return true;
} // QUICPlugin::quic_decrypt_payload

bool QUICParser::quicCheckFrameType(uint8_t* where, FRAME_TYPE frameType)
{
	return (*where) == frameType;
}

inline void QUICParser::quicSkipAck1(uint8_t* start, uint64_t& offset)
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
	offset++;
	quicGetVariableLength(start, offset);
	quicGetVariableLength(start, offset);
	uint64_t quicAckRangeCount = quicGetVariableLength(start, offset);

	quicGetVariableLength(start, offset);

	for (uint64_t x = 0; x < quicAckRangeCount; x++) {
		quicGetVariableLength(start, offset);
		quicGetVariableLength(start, offset);
	}
	return;
}

inline void QUICParser::quicSkipAck2(uint8_t* start, uint64_t& offset)
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
	offset++;
	quicGetVariableLength(start, offset);
	quicGetVariableLength(start, offset);
	uint64_t quicAckRangeCount = quicGetVariableLength(start, offset);

	quicGetVariableLength(start, offset);

	for (uint64_t x = 0; x < quicAckRangeCount; x++) {
		quicGetVariableLength(start, offset);
		quicGetVariableLength(start, offset);
	}
	quicGetVariableLength(start, offset);
	quicGetVariableLength(start, offset);
	quicGetVariableLength(start, offset);
	return;
}

inline void QUICParser::quicSkipConnectionClose1(uint8_t* start, uint64_t& offset)
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
	offset++;
	quicGetVariableLength(start, offset);
	quicGetVariableLength(start, offset);
	uint64_t reasonPhraseLength = quicGetVariableLength(start, offset);

	offset += reasonPhraseLength;
	return;
}

inline void QUICParser::quicSkipConnectionClose2(uint8_t* start, uint64_t& offset)
{
	// https://www.rfc-editor.org/rfc/rfc9000.html#name-connection_close-frames
	offset++;
	quicGetVariableLength(start, offset);
	uint64_t reasonPhraseLength = quicGetVariableLength(start, offset);

	offset += reasonPhraseLength;
	return;
}

inline void QUICParser::quicCopyCrypto(uint8_t* start, uint64_t& offset)
{
	offset += 1;
	uint16_t frameOffset = quicGetVariableLength(start, offset);
	uint16_t frameLength = quicGetVariableLength(start, offset);

	memcpy(m_assembled_payload + frameOffset, start + offset, frameLength);
	if (frameOffset < m_quic_crypto_start) {
		m_quic_crypto_start = frameOffset;
	}
	m_quic_crypto_len += frameLength;
	offset += frameLength;
	return;
}

bool QUICParser::quicReassembleFrames()
{
	m_quic_crypto_start = UINT16_MAX;
	m_quic_crypto_len = 0;

	uint64_t offset = 0;
	uint8_t* payloadEnd = m_decrypted_payload + m_payload_len;
	uint8_t* current = m_decrypted_payload + offset;

	while (quicCheckPointerPos(current, payloadEnd)) {
		// https://www.rfc-editor.org/rfc/rfc9000.html#name-frames-and-frame-types
		// only those frames can occure in initial packets
		if (quicCheckFrameType(current, CRYPTO)) {
			quicCopyCrypto(m_decrypted_payload, offset);
		} else if (quicCheckFrameType(current, ACK1)) {
			quicSkipAck1(m_decrypted_payload, offset);
		} else if (quicCheckFrameType(current, ACK2)) {
			quicSkipAck1(m_decrypted_payload, offset);
		} else if (quicCheckFrameType(current, CONNECTION_CLOSE1)) {
			quicSkipConnectionClose1(m_decrypted_payload, offset);
		} else if (quicCheckFrameType(current, CONNECTION_CLOSE2)) {
			quicSkipConnectionClose2(m_decrypted_payload, offset);
		} else if (
			quicCheckFrameType(current, PADDING) || quicCheckFrameType(current, PING)) {
			offset++;
		} else {
			DEBUG_MSG("Wrong Frame type read during frames assemble\n");
			return false;
		}
		current = m_decrypted_payload + offset;
	}

	if (m_quic_crypto_start == UINT16_MAX)
		return false;

	m_final_payload = m_assembled_payload;
	return true;
} // QUICParser::quic_reassemble_frames

void QUICParser::quicInitialzeArrays()
{
	// buffer for decrypted payload
	memset(m_decrypted_payload, 0, CURRENT_BUFFER_SIZE);
	// buffer for reassembled payload
	memset(m_assembled_payload, 0, CURRENT_BUFFER_SIZE);
	// buffer for quic header
	memset(m_tmp_header_mem, 0, MAX_HEADER_LEN);
}

bool QUICParser::quicCheckInitial(uint8_t packet0)
{
	// version 1 (header form:long header(1) | fixed bit:fixed(1) | long packet type:initial(00) -->
	// 1100 --> C)
	if ((packet0 & 0xF0) == 0xC0) {
		m_is_version2 = false;
		return true;
	}
	// version 2 (header form:long header(1) | fixed bit:fixed(1) | long packet type:initial(01) -->
	// 1101 --> D)
	else if ((packet0 & 0xF0) == 0xD0) {
		m_is_version2 = true;
		return true;
	} else {
		return false;
	}
}

bool QUICParser::quicInitialChecks(const Packet& pkt)
{
	// Port check, Initial packet check and UDP check
	if (pkt.ipProto != 17 || !quicCheckInitial(pkt.payload[0]) || pkt.dstPort != 443) {
		DEBUG_MSG("Packet is not Initial or does not contains LONG HEADER or is not on port 443\n");
		return false;
	}
	return true;
}

bool QUICParser::quicParseHeader(const Packet& pkt)
{
	const uint8_t* payloadPointer = pkt.payload;
	uint64_t offset = 0;

	const uint8_t* payloadEnd = payloadPointer + pkt.payloadLen;

	m_quic_h1 = (quic_first_ver_dcidlen*) (payloadPointer + offset);

	if (!quicObtainVersion()) {
		DEBUG_MSG("Error, version not supported\n");
		return false;
	}

	offset += sizeof(quic_first_ver_dcidlen);

	if (!quicCheckPointerPos((payloadPointer + offset), payloadEnd)) {
		return false;
	}

	if (m_quic_h1->dcidLen != 0) {
		m_dcid = (payloadPointer + offset);
		offset += m_quic_h1->dcidLen;
	}

	if (!quicCheckPointerPos((payloadPointer + offset), payloadEnd)) {
		return false;
	}

	m_quic_h2 = (quic_scidlen*) (payloadPointer + offset);

	offset += sizeof(quic_scidlen);

	if (!quicCheckPointerPos((payloadPointer + offset), payloadEnd)) {
		return false;
	}

	if (m_quic_h2->scidLen != 0) {
		offset += m_quic_h2->scidLen;
	}

	if (!quicCheckPointerPos((payloadPointer + offset), payloadEnd)) {
		return false;
	}

	uint64_t tokenLength = quicGetVariableLength(payloadPointer, offset);

	if (!quicCheckPointerPos((payloadPointer + offset), payloadEnd)) {
		return false;
	}

	offset += tokenLength;

	if (!quicCheckPointerPos((payloadPointer + offset), payloadEnd)) {
		return false;
	}

	m_payload_len = quicGetVariableLength(payloadPointer, offset);
	if (m_payload_len > CURRENT_BUFFER_SIZE) {
		return false;
	}

	if (!quicCheckPointerPos((payloadPointer + offset), payloadEnd)) {
		return false;
	}

	m_pkn = (payloadPointer + offset);

	m_payload = (payloadPointer + offset);

	offset += sizeof(uint8_t) * 4;
	m_sample = (payloadPointer + offset);

	if (!quicCheckPointerPos((payloadPointer + offset), payloadEnd)) {
		return false;
	}

	return true;
} // QUICPlugin::quic_parse_data

bool QUICParser::quicStart(const Packet& pkt)
{
	if (!quicInitialChecks(pkt)) {
		return false;
	}

	quicInitialzeArrays();
	if (!quicParseHeader(pkt)) {
		DEBUG_MSG("Error, parsing header failed\n");
		return false;
	}
	if (!quicCreateInitialSecrets()) {
		DEBUG_MSG("Error, creation of initial secrets failed (client side)\n");
		return false;
	}
	if (!quicDecryptHeader(pkt)) {
		DEBUG_MSG("Error, header decryption failed (client side)\n");
		return false;
	}
	if (!quicDecryptPayload()) {
		DEBUG_MSG("Error, payload decryption failed (client side)\n");
		return false;
	}
	if (!quicReassembleFrames()) {
		DEBUG_MSG("Error, reassembling of crypto frames failed (client side)\n");
		return false;
	}
	if (!quicParseTls()) {
		DEBUG_MSG("SNI and User Agent Extraction failed\n");
		return false;
	}
	return true;
}
} // namespace ipxp
