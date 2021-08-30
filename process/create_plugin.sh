#!/bin/bash

echo "Enter new plugin name (will be converted to lowercase): "
read PLUGIN

echo "Enter your name and email address (format: NAME SURNAME <EMAIL-ADDRESS>): "
read AUTHOR

PLUGIN="$(tr '[:upper:]' '[:lower:]' <<<"$PLUGIN")"
PLUGIN_UPPER="$(tr '[:lower:]' '[:upper:]' <<<"$PLUGIN")"

# Usage: print_basic_info <FILE-EXTENSION>
print_basic_info() {
   echo "/**
 * \\file ${PLUGIN}plugin.${1}
 * \\brief Plugin for parsing ${PLUGIN} traffic.
 * \\author ${AUTHOR}
 * \\date $(date +%Y)
 */"
}

print_license() {
   echo "/*
 * Copyright (C) $(date +%Y) CESNET
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
"
}

print_hpp_code() {
   echo "#ifndef IPXP_PROCESS_${PLUGIN_UPPER}_HPP
#define IPXP_PROCESS_${PLUGIN_UPPER}_HPP

#include <cstring>

#ifdef WITH_NEMEA
  #include \"fields.h\"
#endif

#include <ipfixprobe/process.hpp>
#include <ipfixprobe/flowifc.hpp>
#include <ipfixprobe/packet.hpp>

namespace ipxp {

/**
 * \\brief Flow record extension header for storing parsed ${PLUGIN_UPPER} packets.
 */
struct RecordExt${PLUGIN_UPPER} : RecordExt {

   RecordExt${PLUGIN_UPPER}() : RecordExt(${PLUGIN})
   {
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      return 0;
   }
};

/**
 * \\brief Flow cache plugin for parsing ${PLUGIN_UPPER} packets.
 */
class ${PLUGIN_UPPER}Plugin : public FlowCachePlugin
{
public:
   ${PLUGIN_UPPER}Plugin();
   ~${PLUGIN_UPPER}Plugin();
   void init(const char *params);
   void close();
   OptionsParser *get_parser() const { return new OptionsParser("${PLUGIN}", "Parse ${PLUGIN_UPPER} traffic"); }
   std::string get_name() const { return "${PLUGIN}"; }
   int get_ext_id() { return ${PLUGIN}; }
   const char **get_ipfix_string();
   std::string get_unirec_field_string();
   FlowCachePlugin *copy();

   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
};

}
#endif /* IPXP_PROCESS_${PLUGIN_UPPER}_HPP */
"
}

print_cpp_code() {
   echo "#include <iostream>

#include \"${PLUGIN}plugin.hpp\"
#include <ipfixprobe/ipfix-elements.hpp>

namespace ipxp {

__attribute__((constructor)) static void register_this_plugin()
{
   static PluginRecord rec = PluginRecord(\"${PLUGIN}\", [](){return new ${PLUGIN_UPPER}Plugin();});
   register_plugin(&rec);
}

#define ${PLUGIN_UPPER}_UNIREC_TEMPLATE \"\" /* TODO: unirec template */

UR_FIELDS (
   /* TODO: unirec fields definition */
)

${PLUGIN_UPPER}Plugin::${PLUGIN_UPPER}Plugin()
{
}

${PLUGIN_UPPER}Plugin::~${PLUGIN_UPPER}Plugin()
{
}

void ${PLUGIN_UPPER}Plugin::init(const char *params)
{
}

void ${PLUGIN_UPPER}Plugin::close()
{
}

FlowCachePlugin *${PLUGIN_UPPER}Plugin::copy()
{
   return new ${PLUGIN_UPPER}Plugin(*this);
}

int ${PLUGIN_UPPER}Plugin::pre_create(Packet &pkt)
{
   return 0;
}

int ${PLUGIN_UPPER}Plugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int ${PLUGIN_UPPER}Plugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int ${PLUGIN_UPPER}Plugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void ${PLUGIN_UPPER}Plugin::pre_export(Flow &rec)
{
}

void ${PLUGIN_UPPER}Plugin::finish()
{
   if (print_stats) {
      //sd::cout << \"${PLUGIN_UPPER} plugin stats:\" << std::endl;
   }
}

const char *ipfix_${PLUGIN}_template[] = {
   IPFIX_${PLUGIN_UPPER}_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **${PLUGIN_UPPER}Plugin::get_ipfix_string()
{
   return ipfix_${PLUGIN}_template;
}

std::string ${PLUGIN_UPPER}Plugin::get_unirec_field_string()
{
   return ${PLUGIN_UPPER}_UNIREC_TEMPLATE;
}

}
"
}

print_todo() {
   echo "Generated ${PLUGIN}plugin.cpp and ${PLUGIN}plugin.h files"
   echo
   echo "TODO:"
   echo "1) Add '${PLUGIN}.hpp' and '${PLUGIN}.cpp' files to ipfixprobe_process_src variable in Makefile.am"
   echo "2) Update README.md"
   echo "3.1) Add unirec fields to the UR_FIELDS and ${PLUGIN_UPPER}_UNIREC_TEMPLATE macro in ${PLUGIN}.cpp"
   echo "3.2) Add IPFIX template macro 'IPFIX_${PLUGIN_UPPER}_TEMPLATE' to ipfixprobe/ipfix-elements.hpp"
   echo "3.3) Define IPFIX fields"
   echo "3.4) Write function 'fillIPFIX' in ${PLUGIN}.hpp to fill fields to IPFIX message"
   echo "4) Do the final work in ${PLUGIN}.cpp and ${PLUGIN}.hpp files - implement pre_create, post_create, pre_update, post_update, pre_export and fill_unirec functions (also read and understand when these functions are called, info in ipfixprobe/output.hpp file)"
   echo "5) Be happy with your new awesome ${PLUGIN} plugin!"
   echo
   echo "Optional work:"
   echo "1) Add pcap traffic sample for ${PLUGIN} plugin to pcaps directory"
   echo "2) Add test for ${PLUGIN} to tests directory"
   echo
   echo "NOTE: If you didn't modify pre_create, post_create, pre_update, post_update, pre_export functions, please remove them from ${PLUGIN}.cpp and ${PLUGIN}.hpp"
}

create_hpp_file() {
   FILE="${PLUGIN}.hpp"

   echo "Creating ${FILE} file..."
   print_basic_info hpp >"${FILE}"
   print_license        >>"${FILE}"
   print_hpp_code       >>"${FILE}"
}

create_cpp_file() {
   FILE="${PLUGIN}.cpp"

   echo "Creating ${FILE} file..."
   print_basic_info cpp >"${FILE}"
   print_license        >>"${FILE}"
   print_cpp_code       >>"${FILE}"
}

create_hpp_file
create_cpp_file
echo
print_todo