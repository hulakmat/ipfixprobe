#include <cstdio>
#include <cstring>
#include <iostream>
#include <nfb/nfb.h>
#include <numa.h>
#include <unistd.h>

#include "ndpreader.h"
#include "ndpreader.hpp"

/**
 * \brief Constructor.
 */
NdpReader::NdpReader(uint16_t packetBufferSize, uint64_t timeout)
	: m_dev_handle(nullptr)
	, m_rx_handle(NULL)
	, m_processed_packets(0)
	, m_packet_bufferSize(packetBufferSize)
	, m_timeout(timeout)
{
	m_ndp_packet_buffer = new struct ndp_packet[m_packet_bufferSize];
	m_ndp_packet_buffer_processed = 0;
	m_ndp_packet_buffer_packets = 0;
	m_ndp_packet_buffer_valid = false;
}

/**
 * \brief Destructor.
 */
NdpReader::~NdpReader()
{
	this->close();
}

/**
 * \brief Initialize network interface for reading.
 * \param [in] interface Interface name.
 * \return 0 on success, non 0 on failure + error_msg is filled with error message
 */
int NdpReader::initInterface(const std::string& interface)
{
	std::string pInterface = interface;
	int channel = 0;
	std::size_t delFound = interface.find_last_of(":");
	if (delFound != std::string::npos) {
		std::string channelStr = interface.substr(delFound + 1);
		pInterface = interface.substr(0, delFound);
		channel = std::stoi(channelStr);
	}
	// Open NFB
	std::cout << "Opening device: " << pInterface.c_str() << " Channel: " << channel << std::endl;
	m_dev_handle = nfb_open(pInterface.c_str()); // path to NFB device
	if (!m_dev_handle) {
		errorMsg = std::string() + "unable to open NFB device '" + pInterface + "'";
		return 1;
	}

	struct bitmask* bits = nullptr;
	int nodeId;
	m_rx_handle = ndp_open_rx_queue(m_dev_handle, channel);
	if (!m_rx_handle) {
		errorMsg = std::string() + "error opening NDP queue of NFB device";
		return 1;
	}
	if (((nodeId = ndp_queue_get_numa_node(m_rx_handle)) >= 0)
		&& // OPTIONAL: bind thread to correct NUMA node
		((bits = numa_allocate_nodemask()) != nullptr)) {
		(void) numa_bitmask_setbit(bits, nodeId);
		numa_bind(bits);
		numa_free_nodemask(bits);
	} else {
		errorMsg = std::string() + "warning - NUMA node binding failed\n";
		return 1;
	}
	if (ndp_queue_start(m_rx_handle)) { // start capturing data from NDP queue
		errorMsg = std::string() + "error starting NDP queue on NFB device";
		return 1;
	}
	return 0;
}

/**
 * \brief Close opened file or interface.
 */
void NdpReader::close()
{
	if (m_rx_handle) {
		ndp_queue_stop(m_rx_handle);
		ndp_close_rx_queue(m_rx_handle);
		m_rx_handle = nullptr;
	}
	if (m_dev_handle) { // close NFB device
		nfb_close(m_dev_handle);
		m_dev_handle = nullptr;
	}
	if (m_ndp_packet_buffer) {
		delete[] m_ndp_packet_buffer;
		m_ndp_packet_buffer = nullptr;
	}
}

void NdpReader::printStats()
{
	std::cout << "NFB Reader processed packets: " << m_processed_packets << std::endl;
}

bool NdpReader::retrieveNdpPackets()
{
	int ret;
	if (m_ndp_packet_buffer_valid) {
		ndp_rx_burst_put(m_rx_handle);
		m_ndp_packet_buffer_valid = false;
	}
	ret = ndp_rx_burst_get(m_rx_handle, m_ndp_packet_buffer, m_packet_bufferSize);
	if (ret > 0) {
		m_ndp_packet_buffer_processed = 0;
		m_ndp_packet_buffer_packets = ret;
		m_ndp_packet_buffer_valid = true;
		return true;
	} else if (ret < 0) {
		std::cerr << "RX Burst error: " << ret << std::endl;
	}

	return false;
}

int NdpReader::getPkt(struct ndp_packet** ndpPacketOut, struct NdpHeader** ndpHeaderOut)
{
	if (m_ndp_packet_buffer_processed >= m_ndp_packet_buffer_packets) {
		if (!retrieveNdpPackets()) {
			return 0;
		}
	}

	struct ndp_packet* ndpPacket = (m_ndp_packet_buffer + m_ndp_packet_buffer_processed);
	*ndpPacketOut = ndpPacket;
	*ndpHeaderOut = (struct NdpHeader*) ndpPacket->header;

	m_processed_packets++;
	m_ndp_packet_buffer_processed++;

	return 1;
}

#ifdef __cplusplus
extern "C" {
#endif

void ndpReaderInit(struct NdpReaderContext* context)
{
	context->reader = new NdpReader();
}
void ndpReaderFree(struct NdpReaderContext* context)
{
	delete ((NdpReader*) context->reader);
}
int ndpReaderInitInterface(struct NdpReaderContext* context, const char* interface)
{
	return ((NdpReader*) context->reader)->initInterface(std::string(interface));
}
void ndpReaderPrintStats(struct NdpReaderContext* context)
{
	((NdpReader*) context->reader)->printStats();
}
void ndpReaderClose(struct NdpReaderContext* context)
{
	((NdpReader*) context->reader)->close();
}
int ndpReaderGetPkt(
	struct NdpReaderContext* context,
	struct ndp_packet** ndpPacket,
	struct NdpHeader** ndpHeader)
{
	return ((NdpReader*) context->reader)->getPkt(ndpPacket, ndpHeader);
}
const char* ndpReaderErrorMsg(struct NdpReaderContext* context)
{
	return ((NdpReader*) context->reader)->errorMsg.c_str();
}

#ifdef __cplusplus
}
#endif
