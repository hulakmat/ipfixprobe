/**
 * \file ring.c
 * \author Lukas Hutak <lukas.hutak@cesnet.cz>
 * \brief Ring buffer for messages (source file)
 * \date 2018
 */

/* Copyright (C) 2018 CESNET, z.s.p.o.
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

#define ISO_C11_SOURCE
#include <stdlib.h> // aligned_malloc
//#include <unistd.h>
#include <pthread.h>
#include <time.h>

#include <ipfixprobe/ring.h>

// START TODO: move into header files
#include <assert.h>
#include <inttypes.h>
#include <stdalign.h>

#ifdef DEBUG_RING
#define IPX_ERROR(mod, format, ...) fprintf(stderr, "%s: " format, mod, ##__VA_ARGS__)
#define IPX_WARNING(mod, format, ...) fprintf(stderr, "%s: " format, mod, ##__VA_ARGS__)
#else
#define IPX_ERROR(mod, format, ...)
#define IPX_WARNING(mod, format, ...)
#endif

#ifndef IPX_CLINE_SIZE
/** Expected CPU cache-line size        */
#define IPX_CLINE_SIZE 64
#endif

/** User specific cache-line alignment  */
#define __ipx_aligned(x) __attribute__((__aligned__(x)))
/** Cache-line alignment                */
#define IPX_CACHE_ALIGNED __ipx_aligned(IPX_CLINE_SIZE)
// END

/** Internal identification of the ring buffer */
static const char* g_module = "Ring buffer";

/** \brief Data structure for a reader only */
struct ring_reader {
	/**
	 * \brief Reader head in the buffer (start of the next read operation)
	 * \note Value range [0..size - 1]. Must NOT point behind the end of the buffer.
	 */
	uint32_t dataIdx;
	/**
	 * \brief Reader head (start of the next read operation)
	 * \warning Not limited by the buffer's boundary. Overflow is expected behavior.
	 * \note Value range [0..UINT32_MAX].
	 */
	uint32_t readIdx;
	/**
	 * \brief Last known index of writer head (start of the data that still belongs to a writer)
	 * \note In other words, a reader can read up to here (exclusive!).
	 * \note Value range [0..UINT32_MAX].
	 */
	uint32_t exchangeIdx;
	/**
	 * \brief Reader index of the last sync with a writer (update of the sync structure)
	 * \note Value range [0..UINT32_MAX]. Based on #read_idx.
	 */
	uint32_t readCommitIdx;
	/** \brief Total size of the ring buffer (number of pointers)                    */
	uint32_t size;
	/**
	 * \brief Size of a synchronization block
	 * \note After writing at least this amount of data, update synchronization structure.
	 */
	uint32_t divBlock;

	/** Previously read messages - only 0 or 1 */
	uint32_t last;
};

/** \brief Data structure for writers only */
struct ring_writer {
	/**
	 * \brief Writer head in the buffer (start of the next write operation)
	 * \note Value range [0..size - 1]. Must NOT point behind the end of the buffer.
	 */
	uint32_t dataIdx;
	/**
	 * \brief Writer head (start of the next write operation)
	 * \warning This value can be read by a reader! Therefore, modification MUST be always atomic.
	 * \warning Not limited by the buffer's boundary. Overflow is expected behavior.
	 * \note Value range [0..UINT32_MAX].
	 */
	uint32_t writeIdx;
	/**
	 * \brief Last known index of reader head (start of the data that still belongs to a reader)
	 * \note In other words, a writer can write up to here (exclusive!).
	 * \note Value range [0..UINT32_MAX].
	 */
	uint32_t exchangeIdx;
	/**
	 * \brief Writer index of the last sync with a reader (update of the sync structure)
	 * \note Value range [0..UINT32_MAX]. Based on #write_idx.
	 */
	uint32_t writeCommitIdx;
	/** \brief Total size of the ring buffer (number of pointers)                    */
	uint32_t size;
	/**
	 * \brief Size of a synchronization block
	 * \note After writing at least this amount of data, update synchronization structure.
	 */
	uint32_t divBlock;
};

/** \brief Exchange data structure for reader and writers */
struct ring_sync {
	/**
	 * \brief Reader head
	 * \note End of data read by a reader, i.e. a writer can write up to here (exclusive!).
	 * \note Value range [0..UINT32_MAX].
	 */
	uint32_t writeIdx;
	/**
	 * \brief Writer head
	 * \note End of data written by a writer, i.e. a reader can read up to here (exclusive!).
	 * \note Value range [0..UINT32_MAX].
	 */
	uint32_t readIdx;
	/** \brief Synchronization mutex (MUST be always used to access data structures here)    */
	pthread_mutex_t mutex;

	/** \brief Reader condition variable (empty buffer) */
	pthread_cond_t condReader;
	/** \brief Writer condition variable (full buffer)  */
	pthread_cond_t condWriter;
};

/** \brief Ring buffer */
struct ipx_ring {
	/** A Reader only structure (cache aligned)         */
	struct ring_reader reader IPX_CACHE_ALIGNED;
	/** Writers only structure (cache aligned)          */
	struct ring_writer writer IPX_CACHE_ALIGNED;
	/** Writer lock                                     */
	pthread_spinlock_t writerLock IPX_CACHE_ALIGNED;
	/** Synchronization structure (cache-aligned)       */
	struct ring_sync sync IPX_CACHE_ALIGNED;
	/** Multiple writers mode                           */
	bool mwMode;
	/** Ring data (array of pointers)                   */
	ipx_msg_t** data;
};

ipx_ring_t* ipxRingInit(uint32_t size, bool mwMode)
{
	ipx_ring_t* ring;

	// Prepare data structures
	ring = aligned_alloc(alignof(struct ipx_ring), sizeof(struct ipx_ring));
	if (!ring) {
		IPX_ERROR(module, "aligned_alloc() failed! (%s:%d)", __FILE__, __LINE__);
		return NULL;
	}

	ring->data = aligned_alloc(alignof(*ring->data), sizeof(*ring->data) * size);
	if (!ring->data) {
		IPX_ERROR(module, "aligned_alloc() failed! (%s:%d)", __FILE__, __LINE__);
		goto exit_A;
	}

	// Initialize writers' spin lock
	int rc;
	if ((rc = pthread_spin_init(&ring->writerLock, PTHREAD_PROCESS_PRIVATE)) != 0) {
		IPX_ERROR(module, "pthread_spin_init() failed! (%s:%d, err: %d)", __FILE__, __LINE__, rc);
		goto exit_B;
	}

	// Initialize sync mutex and conditional variables
	if ((rc = pthread_mutex_init(&ring->sync.mutex, NULL)) != 0) {
		IPX_ERROR(module, "pthread_mutex_init() failed! (%s:%d, err: %d)", __FILE__, __LINE__, rc);
		goto exit_C;
	}

	pthread_condattr_t condAttr;
	if ((rc = pthread_condattr_init(&condAttr)) != 0) {
		IPX_ERROR(
			module,
			"pthread_condattr_init() failed! (%s:%d, err: %d)",
			__FILE__,
			__LINE__,
			rc);
		goto exit_D;
	}

	if ((rc = pthread_condattr_setclock(&condAttr, CLOCK_MONOTONIC)) != 0) {
		IPX_ERROR(
			module,
			"pthread_condattr_setclock() failed! (%s:%d, err: %d)",
			__FILE__,
			__LINE__,
			rc);
		goto exit_E;
	}

	if ((rc = pthread_cond_init(&ring->sync.condReader, &condAttr)) != 0) {
		IPX_ERROR(module, "pthread_cond_init() failed! (%s:%d, err: %d)", __FILE__, __LINE__, rc);
		goto exit_E;
	}

	if ((rc = pthread_cond_init(&ring->sync.condWriter, &condAttr)) != 0) {
		IPX_ERROR(module, "pthread_cond_init() failed! (%s:%d, err: %d)", __FILE__, __LINE__, rc);
		goto exit_F;
	}
	pthread_condattr_destroy(&condAttr);

	// Initialize ring variables
	ring->reader.size = size;
	ring->reader.divBlock = size / 8;
	ring->reader.dataIdx = 0;
	ring->reader.readIdx = 0;
	ring->reader.exchangeIdx = 0;
	ring->reader.readCommitIdx = 0;
	ring->reader.last = 0;

	ring->writer.size = size;
	ring->writer.divBlock = size / 8;
	ring->writer.dataIdx = 0;
	ring->writer.exchangeIdx = size; // Amount of empty memory
	ring->writer.writeIdx = 0;
	ring->writer.writeCommitIdx = 0;

	ring->sync.readIdx = 0;
	ring->sync.writeIdx = size;

	ring->mwMode = mwMode;
	return ring;

	// In case failure
exit_F:
	pthread_cond_destroy(&ring->sync.condReader);
exit_E:
	pthread_condattr_destroy(&condAttr);
exit_D:
	pthread_mutex_destroy(&ring->sync.mutex);
exit_C:
	pthread_spin_destroy(&ring->writerLock);
exit_B:
	free(ring->data);
exit_A:
	free(ring);
	return NULL;
}

void ipxRingDestroy(ipx_ring_t* ring)
{
	// The last read message is not confirmed by the reader, it is 1 index behind -> "+ 1"
	if (ring->reader.readIdx != ring->writer.writeIdx) {
		uint32_t cnt = ring->writer.writeIdx - ring->reader.readIdx;
		IPX_WARNING(
			module,
			"Destroying of a ring buffer that still contains %" PRIu32 " unprocessed message(s)!",
			cnt);
	}

	pthread_cond_destroy(&ring->sync.condWriter);
	pthread_cond_destroy(&ring->sync.condReader);
	pthread_mutex_destroy(&ring->sync.mutex);
	pthread_spin_destroy(&ring->writerLock);
	free(ring->data);
	free(ring);
}

/**
 * \brief Wrapper around condition wait
 * \param[in] cond  Condition variable
 * \param[in] mutex Locked mutex
 * \param[in] msec  Number of milliseconds to wait
 * \return Same as the function pthread_cond_timedwait
 */
static inline int ringCondTimedwait(
	pthread_cond_t* __restrict__ cond,
	pthread_mutex_t* __restrict__ mutex,
	long msec)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_nsec += msec * 1000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_nsec %= 1000000000;
		ts.tv_sec += 1;
	}

	return pthread_cond_timedwait(cond, mutex, &ts);
}

/**
 * \brief Get a new empty field
 *
 * \note The function blocks until a required memory is ready. Before the next call of this
 *   function, the function ipx_ring_commit() MUST be called first, to commit performed
 *   modifications.
 * \param[in] ring Ring buffer
 * \return Pointer to a unused place in the buffer
 */
static inline ipx_msg_t** ipxRingBegin(ipx_ring_t* ring)
{
	// Prepare the next pointer to write
	ipx_msg_t** msg = &ring->data[ring->writer.dataIdx];

	// Is there enough space?
	if (ring->writer.exchangeIdx - ring->writer.writeIdx > 0) {
		return msg;
	}

	// Get an empty space -> reader-writer synchronization
	pthread_mutex_lock(&ring->sync.mutex);
	ring->writer.exchangeIdx = ring->sync.writeIdx;
	while (ring->writer.exchangeIdx - ring->writer.writeIdx == 0) {
		// After sync the buffer is still full, try again later
		pthread_cond_signal(&ring->sync.condReader);
		ringCondTimedwait(&ring->sync.condWriter, &ring->sync.mutex, 10);
		ring->writer.exchangeIdx = ring->sync.writeIdx;
	}
	pthread_cond_signal(&ring->sync.condReader);
	pthread_mutex_unlock(&ring->sync.mutex);

	assert(ring->writer.exchange_idx - ring->writer.write_idx > 0);
	return msg;
}

/**
 * \brief Commit modifications of memory
 * \param[in] ring Ring buffer
 */
static inline void ipxRingCommit(ipx_ring_t* ring)
{
	register uint32_t newIdx = 1;
	ring->writer.dataIdx++;

	if (ring->writer.size == ring->writer.dataIdx) {
		// End of the ring buffer has been reached -> skip to the beginning
		ring->writer.dataIdx = 0;
	}

	// Atomic update of writer index (Note: new_idx will be the same as writer.write_idx)
	newIdx += __sync_fetch_and_add(&ring->writer.writeIdx, newIdx);

	// Sync positions with a reader, if necessary
	if (newIdx - ring->writer.writeCommitIdx >= ring->writer.divBlock) {
		pthread_mutex_lock(&ring->sync.mutex);
		ring->sync.readIdx = newIdx;
		ring->writer.exchangeIdx = ring->sync.writeIdx;
		ring->writer.writeCommitIdx = newIdx;
		pthread_cond_signal(&ring->sync.condReader);
		pthread_mutex_unlock(&ring->sync.mutex);
	}
}

void ipxRingPush(ipx_ring_t* ring, ipx_msg_t* msg)
{
	ipx_msg_t** msgSpace;

	if (ring->mwMode) {
		pthread_spin_lock(&ring->writerLock);
	}

	msgSpace = ipxRingBegin(ring);
	*msgSpace = msg;
	ipxRingCommit(ring);

	if (ring->mwMode) {
		pthread_spin_unlock(&ring->writerLock);
	}
}

ipx_msg_t* ipxRingPop(ipx_ring_t* ring)
{
	// Consider previous memory block as processed
	ring->reader.dataIdx += ring->reader.last;
	ring->reader.readIdx += ring->reader.last;
	ring->reader.last = 0;

	if (ring->reader.size == ring->reader.dataIdx) {
		// The end of the ring buffer has been reached -> skip to the beginning
		ring->reader.dataIdx = 0;
	}

	// Prepare the next pointer to read
	ipx_msg_t** msg = &ring->data[ring->reader.dataIdx];

	// Sync positions with writers, if necessary
	if (ring->reader.readIdx - ring->reader.readCommitIdx >= ring->reader.divBlock) {
		pthread_mutex_lock(&ring->sync.mutex);
		ring->sync.writeIdx += ring->reader.readIdx - ring->reader.readCommitIdx;
		ring->reader.exchangeIdx = ring->sync.readIdx;
		ring->reader.readCommitIdx = ring->reader.readIdx;
		pthread_cond_signal(&ring->sync.condWriter);
		pthread_mutex_unlock(&ring->sync.mutex);
	}

	if (ring->reader.exchangeIdx - ring->reader.readIdx > 0) {
		// Ok, the reader owns this part of the buffer
		// TODO: prefetch
		ring->reader.last = 1;
		return *msg; // Now, we can dereference the pointer
	}

	while (1) {
		// The reader has reached the end of the filled memory -> try to sync
		pthread_mutex_lock(&ring->sync.mutex);
		pthread_cond_signal(&ring->sync.condWriter);
		// Wait until a writer sends a signal or a timeout expires
		ringCondTimedwait(&ring->sync.condReader, &ring->sync.mutex, 10);
		ring->reader.exchangeIdx = ring->sync.readIdx;
		pthread_mutex_unlock(&ring->sync.mutex);

		if (ring->reader.exchangeIdx - ring->reader.readIdx > 0) {
			// TODO: prefetch
			ring->reader.last = 1;
			return *msg; // Now, we can dereference the pointer
		}

		// Writer still didn't perform sync -> try to steal all committed messages from writer
		pthread_mutex_lock(&ring->sync.mutex);
		ring->sync.readIdx = ring->reader.exchangeIdx
			= __sync_fetch_and_add(&ring->writer.writeIdx, 0);
		pthread_mutex_unlock(&ring->sync.mutex);

		if (ring->reader.exchangeIdx - ring->reader.readIdx > 0) {
			// TODO: prefetch
			ring->reader.last = 1;
			return *msg; // Now, we can dereference the pointer
		}
		break;
	}
	return NULL;
}

void ipxRingMwMode(ipx_ring_t* ring, bool mode)
{
	ring->mwMode = mode;
}

IPX_API uint32_t ipxRingCnt(const ipx_ring_t* ring)
{
	return ring->writer.writeIdx - ring->reader.readIdx;
}

IPX_API uint32_t ipxRingSize(const ipx_ring_t* ring)
{
	return ring->reader.size;
}
