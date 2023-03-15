/**
 * \file options.hpp
 * \brief Options parser
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

#ifndef IPXP_OPTIONS_HPP
#define IPXP_OPTIONS_HPP

#include <functional>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace Ipxp {

class OptionsParser {
public:
	static const char DELIM = ';';
	typedef std::function<bool(const char* opt)> OptionParserFunc;
	enum OptionFlags : uint32_t { REQUIRED_ARGUMENT = 1, OPTIONAL_ARGUMENT = 2, NO_ARGUMENT = 4 };

	OptionsParser();
	OptionsParser(const std::string& name, const std::string& info);
	~OptionsParser();
	OptionsParser(OptionsParser& p) = delete;
	OptionsParser(OptionsParser&& p) = delete;
	void operator=(OptionsParser& p) = delete;
	void operator=(OptionsParser&& p) = delete;
	void parse(const char* args) const;
	void parse(int argc, const char** argv) const;
	void usage(std::ostream& os, int indentation = 0, std::string modName = "") const;

protected:
	std::string mName;
	std::string mInfo;
	char mDelim;
	struct Option {
		std::string mShort;
		std::string mLong;
		std::string mHint;
		std::string mDescription;
		OptionParserFunc mParser;
		OptionFlags mFlags;
	};
	std::vector<Option*> mOptions;
	std::map<std::string, Option*> mLong;
	std::map<std::string, Option*> mShort;

	void registerOption(
		std::string argShort,
		std::string argLong,
		std::string argHint,
		std::string description,
		OptionParserFunc parser,
		OptionFlags flags = OptionFlags::REQUIRED_ARGUMENT);
};

class ParserError : public std::runtime_error {
public:
	explicit ParserError(const std::string& msg)
		: std::runtime_error(msg) {};
	explicit ParserError(const char* msg)
		: std::runtime_error(msg) {};
};

} // namespace ipxp
#endif /* IPXP_OPTIONS_HPP */
