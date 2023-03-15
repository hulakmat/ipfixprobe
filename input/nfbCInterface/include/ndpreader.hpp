#ifndef NFBREADER_HPP
#define NFBREADER_HPP

#include "ndpheader.h"
#include <nfb/ndp.h>
#include <stdint.h>
#include <string>

class NdpReader {
public:
	NdpReader(uint16_t packetBufferSize = 50, uint64_t timeout = 300);
	~NdpReader();

	int initInterface(const std::string& interface);
	void printStats();
	void close();
	int getPkt(struct ndp_packet** ndpPacket, struct NdpHeader** ndpHeader);
	std::string errorMsg;

private:
	bool retrieveNdpPackets();
	struct nfb_device* m_dev_handle; // NFB device
	struct ndp_queue* m_rx_handle; // data receiving NDP queue
	uint64_t m_processed_packets;
	uint16_t m_packet_bufferSize;
	uint64_t m_timeout;

	uint16_t m_ndp_packet_buffer_processed;
	uint16_t m_ndp_packet_buffer_packets;
	struct ndp_packet* m_ndp_packet_buffer;
	bool m_ndp_packet_buffer_valid;
};

#endif // NFBREADER_HPP
