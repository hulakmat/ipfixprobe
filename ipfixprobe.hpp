/**
 * \file ipfixprobe.hpp
 * \brief Main exporter objects
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

#ifndef IPXP_IPFIXPROBE_HPP
#define IPXP_IPFIXPROBE_HPP

#include <atomic>
#include <config.h>
#include <csignal>
#include <future>
#include <string>
#include <thread>

#include "pluginmgr.hpp"
#include "workers.hpp"
#include <ipfixprobe/input.hpp>
#include <ipfixprobe/options.hpp>
#include <ipfixprobe/output.hpp>
#include <ipfixprobe/packet.hpp>
#include <ipfixprobe/plugin.hpp>
#include <ipfixprobe/process.hpp>
#include <ipfixprobe/ring.h>
#include <ipfixprobe/storage.hpp>
#include <ipfixprobe/utils.hpp>

namespace Ipxp {

extern const uint32_t g_DEFAULT_IQUEUE_SIZE;
extern const uint32_t g_DEFAULT_OQUEUE_SIZE;
extern const uint32_t g_DEFAULT_FPS;

// global termination variable
extern volatile sig_atomic_t g_terminate_export;
extern volatile sig_atomic_t g_terminate_input;

class IpfixprobeOptParser;
struct ipxp_conf_t;

void signalHandler(int sig);
void registerHandlers();
void error(std::string msg);
void printHelp(ipxp_conf_t& conf, const std::string& arg);
void initPackets(ipxp_conf_t& conf);
bool processPluginArgs(ipxp_conf_t& conf, IpfixprobeOptParser& parser);
void mainLoop(ipxp_conf_t& conf);
int run(int argc, char* argv[]);

class IpfixprobeOptParser : public OptionsParser {
public:
	std::vector<std::string> mInput;
	std::vector<std::string> mStorage;
	std::vector<std::string> mOutput;
	std::vector<std::string> mProcess;
	std::string mPid;
	bool mDaemon;
	uint32_t mIqueue;
	uint32_t mOqueue;
	uint32_t mFps;
	uint32_t mPktBufsize;
	uint32_t mMaxPkts;
	bool mHelp;
	std::string mHelpStr;
	bool mVersion;

	IpfixprobeOptParser()
		: OptionsParser("ipfixprobe", "flow exporter supporting various custom IPFIX elements")
		, mPid("")
		, mDaemon(false)
		, mIqueue(g_DEFAULT_IQUEUE_SIZE)
		, mOqueue(g_DEFAULT_OQUEUE_SIZE)
		, mFps(g_DEFAULT_FPS)
		, mPktBufsize(1600)
		, mMaxPkts(0)
		, mHelp(false)
		, mHelpStr("")
		, mVersion(false)
	{
		mDelim = ' ';

		registerOption(
			"-i",
			"--input",
			"ARGS",
			"Activate input plugin (-h input for help)",
			[this](const char* arg) {
				mInput.push_back(arg);
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-s",
			"--storage",
			"ARGS",
			"Activate storage plugin (-h storage for help)",
			[this](const char* arg) {
				mStorage.push_back(arg);
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-o",
			"--output",
			"ARGS",
			"Activate output plugin (-h output for help)",
			[this](const char* arg) {
				mOutput.push_back(arg);
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-p",
			"--process",
			"ARGS",
			"Activate processing plugin (-h process for help)",
			[this](const char* arg) {
				mProcess.push_back(arg);
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-q",
			"--iqueue",
			"SIZE",
			"Size of queue between input and storage plugins",
			[this](const char* arg) {
				try {
					mIqueue = str2num<decltype(mIqueue)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-Q",
			"--oqueue",
			"SIZE",
			"Size of queue between storage and output plugins",
			[this](const char* arg) {
				try {
					mOqueue = str2num<decltype(mOqueue)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-B",
			"--pbuf",
			"SIZE",
			"Size of packet buffer",
			[this](const char* arg) {
				try {
					mPktBufsize = str2num<decltype(mPktBufsize)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-f",
			"--fps",
			"NUM",
			"Export max flows per second",
			[this](const char* arg) {
				try {
					mFps = str2num<decltype(mFps)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-c",
			"--count",
			"SIZE",
			"Quit after number of packets are processed on each interface",
			[this](const char* arg) {
				try {
					mMaxPkts = str2num<decltype(mMaxPkts)>(arg);
				} catch (std::invalid_argument& e) {
					return false;
				}
				return true;
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-P",
			"--pid",
			"FILE",
			"Create pid file",
			[this](const char* arg) {
				mPid = arg;
				return mPid != "";
			},
			OptionFlags::REQUIRED_ARGUMENT);
		registerOption(
			"-d",
			"--daemon",
			"",
			"Run as a standalone process",
			[this](const char* arg) {
				mDaemon = true;
				return true;
			},
			OptionFlags::NO_ARGUMENT);
		registerOption(
			"-h",
			"--help",
			"PLUGIN",
			"Print help text. Supported help for input, storage, output and process plugins",
			[this](const char* arg) {
				mHelp = true;
				mHelpStr = arg ? arg : "";
				return true;
			},
			OptionFlags::OPTIONAL_ARGUMENT);
		registerOption(
			"-V",
			"--version",
			"",
			"Show version and exit",
			[this](const char* arg) {
				mVersion = true;
				return true;
			},
			OptionFlags::NO_ARGUMENT);
	}
};

struct ipxp_conf_t {
	uint32_t iqueueSize;
	uint32_t oqueueSize;
	uint32_t workerCnt;
	uint32_t fps;
	uint32_t maxPkts;

	PluginManager mgr;
	struct Plugins {
		std::vector<InputPlugin*> input;
		std::vector<StoragePlugin*> storage;
		std::vector<OutputPlugin*> output;
		std::vector<ProcessPlugin*> process;
		std::vector<Plugin*> all;
	} active;

	std::vector<WorkPipeline> pipelines;
	std::vector<OutputWorker> outputs;

	std::vector<std::atomic<InputStats>*> inputStats;
	std::vector<std::atomic<OutputStats>*> outputStats;

	std::vector<std::shared_future<WorkerResult>> inputFut;
	std::vector<std::future<WorkerResult>> outputFut;

	size_t pktBufsize;
	size_t blocksCnt;
	size_t pktsCnt;
	size_t pktDataCnt;

	PacketBlock* blocks;
	Packet* pkts;
	uint8_t* pktData;

	ipxp_conf_t()
		: iqueueSize(g_DEFAULT_IQUEUE_SIZE)
		, oqueueSize(g_DEFAULT_OQUEUE_SIZE)
		, workerCnt(0)
		, fps(0)
		, maxPkts(0)
		, pktBufsize(1600)
		, blocksCnt(0)
		, pktsCnt(0)
		, pktDataCnt(0)
		, blocks(nullptr)
		, pkts(nullptr)
		, pktData(nullptr)
	{
	}

	~ipxp_conf_t()
	{
		g_terminate_input = 1;
		for (auto& it : pipelines) {
			if (it.input.thread->joinable()) {
				it.input.thread->join();
			}
			delete it.input.plugin;
			delete it.input.thread;
			delete it.input.promise;
		}

		for (auto& it : pipelines) {
			delete it.storage.plugin;
		}

		for (auto& it : pipelines) {
			for (auto& itp : it.storage.plugins) {
				delete itp;
			}
		}

		g_terminate_export = 1;
		for (auto& it : outputs) {
			if (it.thread->joinable()) {
				it.thread->join();
			}
			delete it.thread;
			delete it.promise;
			delete it.plugin;
			ipxRingDestroy(it.queue);
		}

		for (auto& it : inputStats) {
			delete it;
		}
		for (auto& it : outputStats) {
			delete it;
		}
	}
};

class IPXPError : public std::runtime_error {
public:
	explicit IPXPError(const std::string& msg)
		: std::runtime_error(msg) {};

	explicit IPXPError(const char* msg)
		: std::runtime_error(msg) {};
};

} // namespace ipxp
#endif /* IPXP_IPFIXPROBE_HPP */
