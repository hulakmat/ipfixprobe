/**
 * \file ipfixprobe.cpp
 * \brief Main exporter objects source
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

#include <config.h>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <memory>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

#include "ipfixprobe.hpp"
#ifdef WITH_LIBUNWIND
#include "stacktrace.hpp"
#endif
#include "stats.hpp"

namespace Ipxp {

volatile sig_atomic_t g_stop = 0;

volatile sig_atomic_t g_terminate_export = 0;
volatile sig_atomic_t g_terminate_input = 0;

const uint32_t g_DEFAULT_IQUEUE_SIZE = 64;
const uint32_t g_DEFAULT_OQUEUE_SIZE = 16536;
const uint32_t g_DEFAULT_FPS = 0; // unlimited

/**
 * \brief Signal handler function.
 * \param [in] sig Signal number.
 */
void signalHandler(int sig)
{
#ifdef WITH_LIBUNWIND
	if (sig == SIGSEGV) {
		st_dump(STDERR_FILENO, sig);
		abort();
	}
#endif
	g_stop = 1;
}

void registerHandlers()
{
	signal(SIGTERM, signalHandler);
	signal(SIGINT, signalHandler);
#ifdef WITH_LIBUNWIND
	signal(SIGSEGV, signal_handler);
#endif
#ifdef WITH_NEMEA
	signal(SIGPIPE, SIG_IGN);
#endif
}

void error(std::string msg)
{
	std::cerr << "Error: " << msg << std::endl;
}

template<typename T>
static void printPluginsHelp(std::vector<Plugin*>& plugins)
{
	for (auto& it : plugins) {
		if (dynamic_cast<T*>(it)) {
			OptionsParser* parser = it->getParser();
			parser->usage(std::cout);
			std::cout << std::endl;
			delete parser;
		}
	}
}

void printHelp(ipxp_conf_t& conf, const std::string& arg)
{
	auto deleter = [&](std::vector<Plugin*>* p) {
		for (auto& it : *p) {
			delete it;
		}
		delete p;
	};
	auto plugins = std::unique_ptr<std::vector<Plugin*>, decltype(deleter)>(
		new std::vector<Plugin*>(conf.mgr.get()),
		deleter);

	if (arg == "input") {
		printPluginsHelp<InputPlugin>(*plugins);
	} else if (arg == "storage") {
		printPluginsHelp<StoragePlugin>(*plugins);
	} else if (arg == "output") {
		printPluginsHelp<OutputPlugin>(*plugins);
	} else if (arg == "process") {
		printPluginsHelp<ProcessPlugin>(*plugins);
	} else {
		Plugin* p;
		try {
			p = conf.mgr.get(arg);
			if (p == nullptr) {
				std::cout << "No help available for " << arg << std::endl;
				return;
			}
		} catch (PluginManagerError& e) {
			error(std::string("when loading plugin: ") + e.what());
			return;
		}
		OptionsParser* parser = p->getParser();
		parser->usage(std::cout);
		delete parser;
		delete p;
	}
}

void processPluginArgline(const std::string& args, std::string& plugin, std::string& params)
{
	size_t delim;

	params = args;
	delim = params.find(OptionsParser::DELIM);

	plugin = params.substr(0, delim);
	params.erase(0, delim == std::string::npos ? delim : delim + 1);

	trimStr(plugin);
	trimStr(params);
}

bool processPluginArgs(ipxp_conf_t& conf, IpfixprobeOptParser& parser)
{
	auto deleter = [&](OutputPlugin::Plugins* p) {
		for (auto& it : *p) {
			delete it.second;
		}
		delete p;
	};
	auto processPlugins = std::unique_ptr<OutputPlugin::Plugins, decltype(deleter)>(
		new OutputPlugin::Plugins(),
		deleter);
	std::string storageName = "cache";
	std::string storageParams = "";
	std::string outputName = "ipfix";
	std::string outputParams = "";

	if (parser.mStorage.size()) {
		processPluginArgline(parser.mStorage[0], storageName, storageParams);
	}
	if (parser.mOutput.size()) {
		processPluginArgline(parser.mOutput[0], outputName, outputParams);
	}

	// Process
	for (auto& it : parser.mProcess) {
		ProcessPlugin* processPlugin = nullptr;
		std::string processParams;
		std::string processName;
		processPluginArgline(it, processName, processParams);
		for (auto& it : *processPlugins) {
			std::string pluginName = it.first;
			if (pluginName == processName) {
				throw IPXPError(processName + " plugin was specified multiple times");
			}
		}
		if (processName == BASIC_PLUGIN_NAME) {
			continue;
		}
		try {
			processPlugin = dynamic_cast<ProcessPlugin*>(conf.mgr.get(processName));
			if (processPlugin == nullptr) {
				throw IPXPError("invalid processing plugin " + processName);
			}

			processPlugin->init(processParams.c_str());
			processPlugins->push_back(std::make_pair(processName, processPlugin));
		} catch (PluginError& e) {
			delete processPlugin;
			throw IPXPError(processName + std::string(": ") + e.what());
		} catch (PluginExit& e) {
			delete processPlugin;
			return true;
		} catch (PluginManagerError& e) {
			throw IPXPError(processName + std::string(": ") + e.what());
		}
	}

	// Output
	ipx_ring_t* outputQueue = ipxRingInit(conf.oqueueSize, 1);
	if (outputQueue == nullptr) {
		throw IPXPError("unable to initialize ring buffer");
	}
	OutputPlugin* outputPlugin = nullptr;
	try {
		outputPlugin = dynamic_cast<OutputPlugin*>(conf.mgr.get(outputName));
		if (outputPlugin == nullptr) {
			ipxRingDestroy(outputQueue);
			throw IPXPError("invalid output plugin " + outputName);
		}

		outputPlugin->init(outputParams.c_str(), *processPlugins);
		conf.active.output.push_back(outputPlugin);
		conf.active.all.push_back(outputPlugin);
	} catch (PluginError& e) {
		ipxRingDestroy(outputQueue);
		delete outputPlugin;
		throw IPXPError(outputName + std::string(": ") + e.what());
	} catch (PluginExit& e) {
		ipxRingDestroy(outputQueue);
		delete outputPlugin;
		return true;
	} catch (PluginManagerError& e) {
		throw IPXPError(outputName + std::string(": ") + e.what());
	}

	{
		std::promise<WorkerResult>* outputRes = new std::promise<WorkerResult>();
		auto outputStats = new std::atomic<OutputStats>();
		conf.outputStats.push_back(outputStats);
		OutputWorker tmp
			= {outputPlugin,
			   new std::thread(
				   outputWorker,
				   outputPlugin,
				   outputQueue,
				   outputRes,
				   outputStats,
				   conf.fps),
			   outputRes,
			   outputStats,
			   outputQueue};
		conf.outputs.push_back(tmp);
		conf.outputFut.push_back(outputRes->get_future());
	}

	// Input
	size_t pipelineIdx = 0;
	for (auto& it : parser.mInput) {
		InputPlugin* inputPlugin = nullptr;
		StoragePlugin* storagePlugin = nullptr;
		std::string inputParams;
		std::string inputName;
		processPluginArgline(it, inputName, inputParams);

		try {
			inputPlugin = dynamic_cast<InputPlugin*>(conf.mgr.get(inputName));
			if (inputPlugin == nullptr) {
				throw IPXPError("invalid input plugin " + inputName);
			}
			inputPlugin->init(inputParams.c_str());
			conf.active.input.push_back(inputPlugin);
			conf.active.all.push_back(inputPlugin);
		} catch (PluginError& e) {
			delete inputPlugin;
			throw IPXPError(inputName + std::string(": ") + e.what());
		} catch (PluginExit& e) {
			delete inputPlugin;
			return true;
		} catch (PluginManagerError& e) {
			throw IPXPError(inputName + std::string(": ") + e.what());
		}

		try {
			storagePlugin = dynamic_cast<StoragePlugin*>(conf.mgr.get(storageName));
			if (storagePlugin == nullptr) {
				throw IPXPError("invalid storage plugin " + storageName);
			}
			storagePlugin->setQueue(outputQueue);
			storagePlugin->init(storageParams.c_str());
			conf.active.storage.push_back(storagePlugin);
			conf.active.all.push_back(storagePlugin);
		} catch (PluginError& e) {
			delete storagePlugin;
			throw IPXPError(storageName + std::string(": ") + e.what());
		} catch (PluginExit& e) {
			delete storagePlugin;
			return true;
		} catch (PluginManagerError& e) {
			throw IPXPError(storageName + std::string(": ") + e.what());
		}

		std::vector<ProcessPlugin*> storageProcessPlugins;
		for (auto& it : *processPlugins) {
			ProcessPlugin* tmp = it.second->copy();
			storagePlugin->addPlugin(tmp);
			conf.active.process.push_back(tmp);
			conf.active.all.push_back(tmp);
			storageProcessPlugins.push_back(tmp);
		}

		std::promise<WorkerResult>* inputRes = new std::promise<WorkerResult>();
		conf.inputFut.push_back(inputRes->get_future());

		auto inputStats = new std::atomic<InputStats>();
		conf.inputStats.push_back(inputStats);

		WorkPipeline tmp
			= {{inputPlugin,
				new std::thread(
					inputStorageWorker,
					inputPlugin,
					storagePlugin,
					conf.iqueueSize,
					conf.maxPkts,
					inputRes,
					inputStats),
				inputRes,
				inputStats},
			   {storagePlugin, storageProcessPlugins}};
		conf.pipelines.push_back(tmp);
		pipelineIdx++;
	}

	return false;
}

void finish(ipxp_conf_t& conf)
{
	bool ok = true;

	// Terminate all inputs
	g_terminate_input = 1;
	for (auto& it : conf.pipelines) {
		it.input.thread->join();
		it.input.plugin->close();
	}

	// Terminate all storages
	for (auto& it : conf.pipelines) {
		for (auto& itp : it.storage.plugins) {
			itp->close();
		}
	}

	// Terminate all outputs
	g_terminate_export = 1;
	for (auto& it : conf.outputs) {
		it.thread->join();
	}

	for (auto& it : conf.pipelines) {
		it.storage.plugin->close();
	}

	std::cout << "Input stats:" << std::endl
			  << std::setw(3) << "#" << std::setw(13) << "packets" << std::setw(13) << "parsed"
			  << std::setw(20) << "bytes" << std::setw(13) << "dropped" << std::setw(16) << "qtime"
			  << std::setw(7) << "status" << std::endl;

	int idx = 0;
	uint64_t totalPackets = 0;
	uint64_t totalParsed = 0;
	uint64_t totalBytes = 0;
	uint64_t totalDropped = 0;
	uint64_t totalQtime = 0;

	for (auto& it : conf.inputFut) {
		WorkerResult res = it.get();
		std::string status = "ok";
		if (res.error) {
			ok = false;
			status = res.msg;
		}
		InputStats stats = conf.inputStats[idx]->load();
		std::cout << std::setw(3) << idx++ << " " << std::setw(12) << stats.packets << " "
				  << std::setw(12) << stats.parsed << " " << std::setw(19) << stats.bytes << " "
				  << std::setw(12) << stats.dropped << " " << std::setw(15) << stats.qtime << " "
				  << std::setw(6) << status << std::endl;
		totalPackets += stats.packets;
		totalParsed += stats.parsed;
		totalBytes += stats.bytes;
		totalDropped += stats.dropped;
		totalQtime += stats.qtime;
	}

	std::cout << std::setw(3) << "SUM" << std::setw(13) << totalPackets << std::setw(13)
			  << totalParsed << std::setw(20) << totalBytes << std::setw(13) << totalDropped
			  << std::setw(16) << totalQtime << std::endl;

	std::cout << std::endl;

	std::cout << "Output stats:" << std::endl
			  << std::setw(3) << "#" << std::setw(13) << "biflows" << std::setw(13) << "packets"
			  << std::setw(20) << "bytes (L4)" << std::setw(13) << "dropped" << std::setw(7)
			  << "status" << std::endl;

	idx = 0;
	for (auto& it : conf.outputFut) {
		WorkerResult res = it.get();
		std::string status = "ok";
		if (res.error) {
			ok = false;
			status = res.msg;
		}
		OutputStats stats = conf.outputStats[idx]->load();
		std::cout << std::setw(3) << idx++ << " " << std::setw(12) << stats.biflows << " "
				  << std::setw(12) << stats.packets << " " << std::setw(19) << stats.bytes << " "
				  << std::setw(12) << stats.dropped << " " << std::setw(6) << status << std::endl;
	}

	if (!ok) {
		throw IPXPError("one of the plugins exitted unexpectedly");
	}
}

void serveStatClients(ipxp_conf_t& conf, struct pollfd pfds[2])
{
	uint8_t buffer[100000];
	size_t written = 0;
	msg_header_t* hdr = (msg_header_t*) buffer;
	int ret = poll(pfds, 2, 0);
	if (ret <= 0) {
		return;
	}
	if (pfds[1].fd > 0 && pfds[1].revents & POLL_IN) {
		ret = recvData(pfds[1].fd, sizeof(uint32_t), buffer);
		if (ret < 0) {
			// Client disconnected
			close(pfds[1].fd);
			pfds[1].fd = -1;
		} else {
			if (*((uint32_t*) buffer) != MSG_MAGIC) {
				return;
			}
			// Received stats request from client
			written += sizeof(msg_header_t);
			for (auto& it : conf.inputStats) {
				InputStats stats = it->load();
				*(InputStats*) (buffer + written) = stats;
				written += sizeof(InputStats);
			}
			for (auto& it : conf.outputStats) {
				OutputStats stats = it->load();
				*(OutputStats*) (buffer + written) = stats;
				written += sizeof(OutputStats);
			}

			hdr->magic = MSG_MAGIC;
			hdr->size = written - sizeof(msg_header_t);
			hdr->inputs = conf.inputStats.size();
			hdr->outputs = conf.outputStats.size();

			sendData(pfds[1].fd, written, buffer);
		}
	}

	if (pfds[0].revents & POLL_IN) {
		int fd = accept(pfds[0].fd, NULL, NULL);
		if (pfds[1].fd == -1) {
			pfds[1].fd = fd;
		} else if (fd != -1) {
			// Close incoming connection
			close(fd);
		}
	}
}

void mainLoop(ipxp_conf_t& conf)
{
	std::vector<std::shared_future<WorkerResult>*> futs;
	for (auto& it : conf.inputFut) {
		futs.push_back(&it);
	}

	struct pollfd pfds[2] = {
		{.fd = -1, .events = POLL_IN}, // Server
		{.fd = -1, .events = POLL_IN} // Client
	};

	std::string sockPath = createSockpath(std::to_string(getpid()).c_str());
	pfds[0].fd = createStatsSock(sockPath.c_str());
	if (pfds[0].fd < 0) {
		error("Unable to create stats socket " + sockPath);
	}

	while (!g_stop && futs.size()) {
		serveStatClients(conf, pfds);

		for (auto it = futs.begin(); it != futs.end(); it++) {
			std::future_status status = (*it)->wait_for(std::chrono::seconds(0));
			if (status == std::future_status::ready) {
				WorkerResult res = (*it)->get();
				if (!res.error) {
					it = futs.erase(it);
					break;
				}
				g_stop = 1;
				break;
			}
		}
		for (auto& it : conf.outputFut) {
			std::future_status status = it.wait_for(std::chrono::seconds(0));
			if (status == std::future_status::ready) {
				g_stop = 1;
				break;
			}
		}

		usleep(1000);
	}

	if (pfds[0].fd != -1) {
		close(pfds[0].fd);
	}
	if (pfds[1].fd != -1) {
		close(pfds[1].fd);
	}
	unlink(sockPath.c_str());
	finish(conf);
}

int run(int argc, char* argv[])
{
	IpfixprobeOptParser parser;
	ipxp_conf_t conf;
	int status = EXIT_SUCCESS;

	registerHandlers();

	try {
		parser.parse(argc - 1, const_cast<const char**>(argv) + 1);
	} catch (ParserError& e) {
		error(e.what());
		status = EXIT_FAILURE;
		goto EXIT;
	}

	if (parser.mHelp) {
		if (parser.mHelpStr.empty()) {
			parser.usage(std::cout, 0, PACKAGE_NAME);
		} else {
			printHelp(conf, parser.mHelpStr);
		}
		goto EXIT;
	}
	if (parser.mVersion) {
		std::cout << PACKAGE_VERSION << std::endl;
		goto EXIT;
	}
	if (parser.mStorage.size() > 1 || parser.mOutput.size() > 1) {
		error("only one storage and output plugin can be specified");
		status = EXIT_FAILURE;
		goto EXIT;
	}
	if (parser.mInput.size() == 0) {
		error("specify at least one input plugin");
		status = EXIT_FAILURE;
		goto EXIT;
	}

	if (parser.mDaemon) {
		if (daemon(1, 0) == -1) {
			error("failed to run as a standalone process");
			status = EXIT_FAILURE;
			goto EXIT;
		}
	}
	if (!parser.mPid.empty()) {
		std::ofstream pidFile(parser.mPid, std::ofstream::out);
		if (pidFile.fail()) {
			error("failed to write pid file");
			status = EXIT_FAILURE;
			goto EXIT;
		}
		pidFile << getpid();
		pidFile.close();
	}

	if (parser.mIqueue < 1) {
		error("input queue size must be at least 1 record");
		status = EXIT_FAILURE;
		goto EXIT;
	}
	if (parser.mOqueue < 1) {
		error("output queue size must be at least 1 record");
		status = EXIT_FAILURE;
		goto EXIT;
	}

	conf.workerCnt = parser.mInput.size();
	conf.iqueueSize = parser.mIqueue;
	conf.oqueueSize = parser.mOqueue;
	conf.fps = parser.mFps;
	conf.pktBufsize = parser.mPktBufsize;
	conf.maxPkts = parser.mMaxPkts;

	try {
		if (processPluginArgs(conf, parser)) {
			goto EXIT;
		}
		mainLoop(conf);
	} catch (std::system_error& e) {
		error(e.what());
		status = EXIT_FAILURE;
		goto EXIT;
	} catch (std::bad_alloc& e) {
		error("not enough memory");
		status = EXIT_FAILURE;
		goto EXIT;
	} catch (IPXPError& e) {
		error(e.what());
		status = EXIT_FAILURE;
		goto EXIT;
	}

EXIT:
	if (!parser.mPid.empty()) {
		unlink(parser.mPid.c_str());
	}
	return status;
}

} // namespace ipxp
