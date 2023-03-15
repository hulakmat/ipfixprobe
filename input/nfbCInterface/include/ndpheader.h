#ifndef NDPHEADER_H
#define NDPHEADER_H

#include <nfb/ndp.h>

#ifdef __cplusplus
extern "C" {
#endif
/**
 * \brief Format of NDP header of data received from NSF firmware.
 */
struct NdpHeader {
	uint8_t interface : 4; //!< Interface number on which the data was captured.
	uint8_t dmaChannel : 4; //!< DMA channel.
	uint8_t crcHash : 4; //!< Precomputed CRC hash (4 bits).
	uint8_t dataType : 4; //!< Format of data that follow this header.
	uint16_t frameSize; //!< Size of captured frame.
	uint32_t timestampNsec; //!< Nanoseconds part of capture timestamp.
	uint32_t timestampSec; //!< Seconds part of capture timestamp.
} __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif // NDPHEADER_H
