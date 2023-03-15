/**
 * \file options.cpp
 * \brief Options parser source
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

#include <iomanip>
#include <string>
#include <vector>

#include <ipfixprobe/options.hpp>
#include <ipfixprobe/utils.hpp>

namespace Ipxp {

OptionsParser::OptionsParser()
	: mName("")
	, mInfo("")
	, mDelim(OptionsParser::DELIM)
{
}

OptionsParser::OptionsParser(const std::string& name, const std::string& info)
	: mName(name)
	, mInfo(info)
	, mDelim(OptionsParser::DELIM)
{
}

OptionsParser::~OptionsParser()
{
	for (const auto& it : mOptions) {
		delete it;
	}
	mOptions.clear();
	mShort.clear();
	mLong.clear();
}

void OptionsParser::parse(const char* args) const
{
	std::vector<std::string> tokens;
	std::vector<const char*> tokenPtrs;
	size_t first = 0;
	size_t last = 0;
	if (args == nullptr || args[0] == 0) {
		parse(0, nullptr);
		return;
	}
	while (1) {
		if (args[last] == mDelim || !args[last]) {
			std::string token = std::string(args, first, last - first);
			size_t pos = token.find("=");
			std::string name = token.substr(0, pos);
			std::string arg;

			tokens.push_back(name);
			if (pos != std::string::npos) {
				arg = token.substr(pos + 1, std::string::npos);
				tokens.push_back(arg);
			}
			first = last + 1;
		}
		if (!args[last]) {
			break;
		}
		last += 1;
	}
	for (const auto& it : tokens) {
		tokenPtrs.push_back(it.c_str());
	}
	parse(tokenPtrs.size(), tokenPtrs.data());
}

void OptionsParser::parse(int argc, const char** argv) const
{
	if (argc && !argv) {
		throw std::runtime_error("invalid arguments passed");
	}
	for (int i = 0; i < argc; i++) {
		Option* optSpec = nullptr;
		std::string opt = argv[i];
		std::string eqParam;
		const char* arg = nullptr;
		size_t eqPos = opt.find("=");
		if (opt.empty()) {
			continue;
		}
		if (eqPos != std::string::npos) {
			eqParam = opt.substr(eqPos + 1);
			opt = opt.erase(eqPos);
		}

		if (mLong.find(opt) != mLong.end()) {
			optSpec = mLong.at(opt);
		} else if (mShort.find(opt) != mShort.end()) {
			optSpec = mShort.at(opt);
		} else {
			throw ParserError("invalid option " + opt);
		}

		if (optSpec->mFlags & OptionFlags::REQUIRED_ARGUMENT) {
			if (eqPos != std::string::npos) {
				arg = eqParam.c_str();
			} else {
				if (i + 1 == argc) {
					throw ParserError("missing argument for option " + opt);
				}
				arg = argv[i + 1];
				i++;
			}
		} else if (optSpec->mFlags & OptionFlags::OPTIONAL_ARGUMENT) {
			if (eqPos != std::string::npos) {
				arg = eqParam.c_str();
			} else {
				if (i + 1 < argc && mLong.find(argv[i + 1]) == mLong.end()
					&& mShort.find(argv[i + 1]) == mShort.end()) {
					arg = argv[i + 1];
					i++;
				}
			}
		}

		if (!optSpec->mParser(arg)) {
			throw ParserError("invalid argument for option " + opt);
		}
	}
}

void OptionsParser::registerOption(
	std::string argShort,
	std::string argLong,
	std::string argHint,
	std::string description,
	OptionParserFunc parser,
	OptionsParser::OptionFlags flags)
{
	if (argShort.empty() || argLong.empty() || description.empty()) {
		throw std::runtime_error(
			"invalid option registration: short, long or description string is missing");
	}

	if (mShort.find(argShort) != mShort.end() || mLong.find(argLong) != mLong.end()) {
		throw std::runtime_error(
			"invalid option registration: option " + argShort + " " + argLong
			+ " already exists");
	}

	Option* opt = new Option();
	opt->mShort = argShort;
	opt->mLong = argLong;
	opt->mHint = argHint;
	opt->mDescription = description;
	opt->mParser = parser;
	opt->mFlags = flags;

	mOptions.push_back(opt);
	mShort[argShort] = opt;
	mLong[argLong] = opt;
}

void OptionsParser::usage(std::ostream& os, int indentation, std::string modName) const
{
	std::string indentStr = std::string(indentation, ' ');
	size_t maxLong = 0;
	size_t maxShort = 0;
	size_t maxReqArg = 0;
	for (const auto& it : mOptions) {
		size_t argLen = it->mFlags & OptionFlags::REQUIRED_ARGUMENT ? it->mHint.size() : 0;
		argLen = it->mFlags & OptionFlags::OPTIONAL_ARGUMENT ? it->mHint.size() + 2 : argLen;

		maxShort = max(maxShort, it->mShort.size());
		maxLong = max(maxLong, it->mLong.size());
		maxReqArg = max(maxReqArg, argLen);
	}

	std::string name = (modName.empty() ? mName : modName);
	std::string usageStr = "Usage: ";
	os << indentStr << name << std::endl;
	os << indentStr << mInfo << std::endl;
	os << indentStr << usageStr << name;
	for (const auto& it : mOptions) {
		std::string argStr = it->mFlags & OptionFlags::REQUIRED_ARGUMENT ? "=" + it->mHint : "";
		argStr = it->mFlags & OptionFlags::OPTIONAL_ARGUMENT ? "[=" + it->mHint + "]" : argStr;
		os << mDelim << it->mLong << argStr;
	}
	os << std::endl;
	if (!mOptions.empty()) {
		os << indentStr << std::string(usageStr.size(), ' ') << name;
		for (const auto& it : mOptions) {
			std::string argStr
				= it->mFlags & OptionFlags::REQUIRED_ARGUMENT ? "=" + it->mHint : "";
			argStr
				= it->mFlags & OptionFlags::OPTIONAL_ARGUMENT ? "[=" + it->mHint + "]" : argStr;
			os << mDelim << it->mShort << argStr;
		}
		os << std::endl;
		os << "Params:" << std::endl;
	}
	indentStr += "  ";
	for (const auto& it : mOptions) {
		std::string argStr = it->mFlags & OptionFlags::REQUIRED_ARGUMENT ? it->mHint : "";
		argStr = it->mFlags & OptionFlags::OPTIONAL_ARGUMENT ? "[" + it->mHint + "]" : argStr;

		os << indentStr << std::setw(maxShort + 1) << std::left << it->mShort
		   << std::setw(maxLong + 1) << std::left << it->mLong << std::setw(maxReqArg + 2)
		   << std::left << argStr << " " + it->mDescription << std::endl;
	}
}

} // namespace ipxp
