#ifndef NDPHEADER_H
#define NDPHEADER_H

#include <nfb/ndp.h>

#ifdef __cplusplus
extern "C" {
#endif
#define NDK_APP_NIC_HEADER

#ifdef NDK_APP_NIC_HEADER
/**
 * \brief Format of NDP APP NIC header.
 */
struct ndp_header {
    union {
	struct {
		uint32_t timestamp_nsec; //!< Nanoseconds part of capture timestamp.
		uint32_t timestamp_sec; //!< Seconds part of capture timestamp.
	};
    	uint64_t timestamp;
    };
    uint16_t vlan_tci;
    uint8_t vlan_flags : 2;
    uint8_t ip_csum_status : 2;
    uint8_t l4_csum_status : 2;
    uint8_t parser_status : 2;
    uint8_t l2_len : 7;
    uint16_t l3_len : 9;
    uint8_t l4_len : 8;
    uint8_t l2_type : 4;
    uint8_t l3_type : 4;
    uint8_t l4_type : 4;

    uint8_t  interface : 4;
    uint64_t hash;

    uint16_t  application_function;
    uint8_t reserved[6];
} __attribute__((__packed__));
#else
/**
 * \brief Format of NDP header of data received from NSF firmware.
 */
struct ndp_header {
    uint8_t  interface : 4; //!< Interface number on which the data was captured.
    uint8_t  dma_channel : 4; //!< DMA channel.
    uint8_t  crc_hash : 4; //!< Precomputed CRC hash (4 bits).
    uint8_t  data_type : 4; //!< Format of data that follow this header.
    uint16_t frame_size; //!< Size of captured frame.
    uint32_t timestamp_nsec; //!< Nanoseconds part of capture timestamp.
    uint32_t timestamp_sec; //!< Seconds part of capture timestamp.
} __attribute__((__packed__));
#endif

#ifdef __cplusplus
}
#endif

#endif //NDPHEADER_H
