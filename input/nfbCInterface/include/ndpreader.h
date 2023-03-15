#ifndef NFBREADER_C_H
#define NFBREADER_C_H

#include "ndpheader.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct NdpReaderContext {
	void* reader;
};

extern void ndpReaderInit(struct NdpReaderContext* context);
extern void ndpReaderFree(struct NdpReaderContext* context);
extern const char* ndpReaderErrorMsg(struct NdpReaderContext* context);
extern int ndpReaderInitInterface(struct NdpReaderContext* context, const char* interface);
extern void ndpReaderPrintStats(struct NdpReaderContext* context);
extern void ndpReaderClose(struct NdpReaderContext* context);
extern int ndpReaderGetPkt(
	struct NdpReaderContext* context,
	struct ndp_packet** ndpPacket,
	struct NdpHeader** ndpHeader);

#ifdef __cplusplus
}
#endif

#endif // NFBREADER_C_H
