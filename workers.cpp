/**
 * \file workers.cpp
 * \brief Exporter worker procedures source
 * \author Jiri Havranek <havranek@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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

#include <sys/time.h>
#include <unistd.h>

#include "ipfixprobe.hpp"
#include "workers.hpp"

namespace Ipxp {

#define MICRO_SEC 1000000L

void inputStorageWorker(
	InputPlugin* plugin,
	StoragePlugin* cache,
	size_t queueSize,
	uint64_t pktLimit,
	std::promise<WorkerResult>* out,
	std::atomic<InputStats>* outStats)
{
	struct timespec startCache;
	struct timespec endCache;
	struct timespec begin = {0, 0};
	struct timespec end = {0, 0};
	struct timeval ts = {0, 0};
	bool timeout = false;
	InputPlugin::Result ret;
	InputStats stats = {0, 0, 0, 0, 0};
	WorkerResult res = {false, ""};

	PacketBlock block(queueSize);

#ifdef __linux__
	const clockid_t clkId = CLOCK_MONOTONIC_COARSE;
#else
	const clockid_t clk_id = CLOCK_MONOTONIC;
#endif

	while (!g_terminate_input) {
		block.cnt = 0;
		block.bytes = 0;

		if (pktLimit && plugin->mParsed + block.size >= pktLimit) {
			if (plugin->mParsed >= pktLimit) {
				break;
			}
			block.size = pktLimit - plugin->mParsed;
		}
		try {
			ret = plugin->get(block);
		} catch (PluginError& e) {
			res.error = true;
			res.msg = e.what();
			break;
		}
		if (ret == InputPlugin::Result::TIMEOUT) {
			clock_gettime(clkId, &end);
			if (!timeout) {
				timeout = true;
				begin = end;
			}
			struct timespec diff = {end.tv_sec - begin.tv_sec, end.tv_nsec - begin.tv_nsec};
			if (diff.tv_nsec < 0) {
				diff.tv_nsec += 1000000000;
				diff.tv_sec--;
			}
			cache->exportExpired(ts.tv_sec + diff.tv_sec);
			usleep(1);
			continue;
		} else if (ret == InputPlugin::Result::PARSED) {
			stats.packets = plugin->mSeen;
			stats.parsed = plugin->mParsed;
			stats.dropped = plugin->mDropped;
			stats.bytes += block.bytes;
			clock_gettime(clkId, &startCache);
			try {
				for (unsigned i = 0; i < block.cnt; i++) {
					cache->putPkt(block.pkts[i]);
				}
				ts = block.pkts[block.cnt - 1].ts;
			} catch (PluginError& e) {
				res.error = true;
				res.msg = e.what();
				break;
			}
			timeout = false;
			clock_gettime(clkId, &endCache);

			int64_t time = endCache.tv_nsec - startCache.tv_nsec;
			if (startCache.tv_sec != endCache.tv_sec) {
				time += 1000000000;
			}
			stats.qtime += time;

			outStats->store(stats);
		} else if (ret == InputPlugin::Result::ERROR) {
			res.error = true;
			res.msg = "error occured during reading";
			break;
		} else if (ret == InputPlugin::Result::END_OF_FILE) {
			break;
		}
	}

	stats.packets = plugin->mSeen;
	stats.parsed = plugin->mParsed;
	stats.dropped = plugin->mDropped;
	outStats->store(stats);
	cache->finish();
	auto outq = cache->getQueue();
	while (ipxRingCnt(outq)) {
		usleep(1);
	}
	out->set_value(res);
}

static long timevalDiff(const struct timeval* start, const struct timeval* end)
{
	return (end->tv_sec - start->tv_sec) * MICRO_SEC + (end->tv_usec - start->tv_usec);
}

void outputWorker(
	OutputPlugin* exp,
	ipx_ring_t* queue,
	std::promise<WorkerResult>* out,
	std::atomic<OutputStats>* outStats,
	uint32_t fps)
{
	WorkerResult res = {false, ""};
	OutputStats stats = {0, 0, 0, 0};
	struct timespec sleepTime = {0};
	struct timeval begin;
	struct timeval end;
	struct timeval lastFlush;
	uint32_t pktsFromBegin = 0;
	double timePerPkt = 0;

	if (fps != 0) {
		timePerPkt = 1000000.0 / fps; // [micro seconds]
	}

	// Rate limiting algorithm from
	// https://github.com/CESNET/ipfixcol2/blob/master/src/tools/ipfixsend/sender.c#L98
	gettimeofday(&begin, nullptr);
	lastFlush = begin;
	while (1) {
		gettimeofday(&end, nullptr);

		Flow* flow = static_cast<Flow*>(ipxRingPop(queue));
		if (!flow) {
			if (end.tv_sec - lastFlush.tv_sec > 1) {
				lastFlush = end;
				exp->flush();
			}
			if (g_terminate_export && !ipxRingCnt(queue)) {
				break;
			}
			continue;
		}

		stats.biflows++;
		stats.bytes += flow->srcBytes + flow->dstBytes;
		stats.packets += flow->srcPackets + flow->dstPackets;
		stats.dropped = exp->mFlowsDropped;
		outStats->store(stats);
		try {
			exp->exportFlow(*flow);
		} catch (PluginError& e) {
			res.error = true;
			res.msg = e.what();
			break;
		}

		pktsFromBegin++;
		if (fps == 0) {
			// Limit for packets/s is not enabled
			continue;
		}

		// Calculate expected time of sending next packet
		long elapsed = timevalDiff(&begin, &end);
		if (elapsed < 0) {
			// Should be never negative. Just for sure...
			elapsed = pktsFromBegin * timePerPkt;
		}

		long nextStart = pktsFromBegin * timePerPkt;
		long diff = nextStart - elapsed;

		if (diff >= MICRO_SEC) {
			diff = MICRO_SEC - 1;
		}

		// Sleep
		if (diff > 0) {
			sleepTime.tv_nsec = diff * 1000L;
			nanosleep(&sleepTime, nullptr);
		}

		if (pktsFromBegin >= fps) {
			// Restart counter
			gettimeofday(&begin, nullptr);
			pktsFromBegin = 0;
		}
	}

	exp->flush();
	stats.dropped = exp->mFlowsDropped;
	outStats->store(stats);
	out->set_value(res);
}

} // namespace ipxp
