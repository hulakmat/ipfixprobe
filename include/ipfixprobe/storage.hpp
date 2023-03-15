/**
 * \file storage.hpp
 * \brief Generic interface of storage plugin
 * \author Vaclav Bartos <bartos@cesnet.cz>
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

#ifndef IPXP_STORAGE_HPP
#define IPXP_STORAGE_HPP

#include <string>

#include "flowifc.hpp"
#include "packet.hpp"
#include "plugin.hpp"
#include "process.hpp"
#include "ring.h"

namespace Ipxp {

/**
 * \brief Base class for flow caches.
 */
class StoragePlugin : public Plugin {
protected:
	ipx_ring_t* mExportQueue;

private:
	ProcessPlugin** m_plugins; /**< Array of plugins. */
	uint32_t m_plugin_cnt;

public:
	StoragePlugin()
		: mExportQueue(nullptr)
		, m_plugins(nullptr)
		, m_plugin_cnt(0)
	{
	}

	virtual ~StoragePlugin()
	{
		if (m_plugins != nullptr) {
			delete[] m_plugins;
		}
	}

	/**
	 * \brief Put packet into the cache (i.e. update corresponding flow record or create a new one)
	 * \param [in] pkt Input parsed packet.
	 * \return 0 on success.
	 */
	virtual int putPkt(Packet& pkt) = 0;

	/**
	 * \brief Set export queue
	 */
	virtual void setQueue(ipx_ring_t* queue) { mExportQueue = queue; }

	/**
	 * \brief Get export queue
	 */
	const ipx_ring_t* getQueue() const { return mExportQueue; }

	virtual void exportExpired(time_t ts) {}
	virtual void finish() {}

	/**
	 * \brief Add plugin to internal list of plugins.
	 * Plugins are always called in the same order, as they were added.
	 */
	void addPlugin(ProcessPlugin* plugin)
	{
		if (m_plugins == nullptr) {
			m_plugins = new ProcessPlugin*[8];
		} else {
			if (m_plugin_cnt % 8 == 0) {
				ProcessPlugin** tmp = new ProcessPlugin*[m_plugin_cnt + 8];
				for (unsigned int i = 0; i < m_plugin_cnt; i++) {
					tmp[i] = m_plugins[i];
				}
				delete[] m_plugins;
				m_plugins = tmp;
			}
		}
		m_plugins[m_plugin_cnt++] = plugin;
	}

protected:
	// Every StoragePlugin implementation should call these functions at appropriate places

	/**
	 * \brief Call pre_create function for each added plugin.
	 * \param [in] pkt Input parsed packet.
	 * \return Options for flow cache.
	 */
	int pluginsPreCreate(Packet& pkt)
	{
		int ret = 0;
		for (unsigned int i = 0; i < m_plugin_cnt; i++) {
			ret |= m_plugins[i]->preCreate(pkt);
		}
		return ret;
	}

	/**
	 * \brief Call post_create function for each added plugin.
	 * \param [in,out] rec Stored flow record.
	 * \param [in] pkt Input parsed packet.
	 * \return Options for flow cache.
	 */
	int pluginsPostCreate(Flow& rec, const Packet& pkt)
	{
		int ret = 0;
		for (unsigned int i = 0; i < m_plugin_cnt; i++) {
			ret |= m_plugins[i]->postCreate(rec, pkt);
		}
		return ret;
	}

	/**
	 * \brief Call pre_update function for each added plugin.
	 * \param [in,out] rec Stored flow record.
	 * \param [in] pkt Input parsed packet.
	 * \return Options for flow cache.
	 */
	int pluginsPreUpdate(Flow& rec, Packet& pkt)
	{
		int ret = 0;
		for (unsigned int i = 0; i < m_plugin_cnt; i++) {
			ret |= m_plugins[i]->preUpdate(rec, pkt);
		}
		return ret;
	}

	/**
	 * \brief Call post_update function for each added plugin.
	 * \param [in,out] rec Stored flow record.
	 * \param [in] pkt Input parsed packet.
	 */
	int pluginsPostUpdate(Flow& rec, const Packet& pkt)
	{
		int ret = 0;
		for (unsigned int i = 0; i < m_plugin_cnt; i++) {
			ret |= m_plugins[i]->postUpdate(rec, pkt);
		}
		return ret;
	}

	/**
	 * \brief Call pre_export function for each added plugin.
	 * \param [in,out] rec Stored flow record.
	 */
	void pluginsPreExport(Flow& rec)
	{
		for (unsigned int i = 0; i < m_plugin_cnt; i++) {
			m_plugins[i]->preExport(rec);
		}
	}
};

} // namespace ipxp
#endif /* IPXP_STORAGE_HPP */
