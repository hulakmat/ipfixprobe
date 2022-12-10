/**
 * \file cache.hpp
 * \brief "FlowStore" Flow store abstraction
 * \author Tomas Benes <tomasbenes@cesnet.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2014-2016 CESNET
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
#ifndef IPXP_FLOW_STORE_STATS_UNIREC_HPP
#define IPXP_FLOW_STORE_STATS_UNIREC_HPP

#include <string>
#include <fstream>
#include "output/unirec.hpp"
#include "flowstoreproxy.hpp"
#include <ipfixprobe/options.hpp>
#include <thread>
#include <libtrap/trap.h>
#include <unirec/unirec.h>


namespace ipxp {


class FlowStoreUnirecWriterStatic
{
protected:
    uint32_t m_instanceId;
    static uint32_t m_instanceIdGlobal;

    void initInstanceId() {
        m_instanceId = m_instanceIdGlobal;
        m_instanceIdGlobal++;
    }
};

class FlowStoreStatsUnirecWriter : private FlowStoreUnirecWriterStatic
{
private:
    std::string m_ifc_spec_str;
    int m_unirec_ifc = 0;
    trap_ctx_t *m_trap_ctx = nullptr;
    ur_template_t *m_template = nullptr;
    void *m_record = nullptr;
public:
    FlowStoreStatsUnirecWriter()  {
    }

    void init(std::string ifc_ptr) {
        m_ifc_spec_str = ifc_ptr;
        if(m_ifc_spec_str.find("%t") != std::string::npos) {
            m_ifc_spec_str = m_ifc_spec_str.replace(m_ifc_spec_str.find("%t"), std::string("%t").size(), std::to_string(m_instanceId));
        }
    }
    ~FlowStoreStatsUnirecWriter() {
        if(m_record) {
            ur_free_record(m_record);
            m_record = nullptr;
        }
        if(m_trap_ctx) {
            trap_ctx_finalize(&m_trap_ctx);
            m_trap_ctx = nullptr;
        }
    }

    void InitializeInterface() {
        if(m_trap_ctx) {
            return;
        }
        if(m_ifc_spec_str.empty()) {
            /* Use Global trap ctx instead of local one. Skip the output interface */
            m_unirec_ifc = m_instanceId+UnirecExporterOutputInterfaces;
            m_trap_ctx = trap_get_global_ctx();
        } else {
            trap_ifc_spec_t ifc_spec;
            std::vector<char> spec_str(m_ifc_spec_str.c_str(), m_ifc_spec_str.c_str() + m_ifc_spec_str.size() + 1);
            char *argv[] = {"-i", spec_str.data(), "-vvv"};
            int argc = 3;

            if (trap_parse_params(&argc, argv, &ifc_spec) != TRAP_E_OK) {
                trap_free_ifc_spec(ifc_spec);
                std::string err_msg = "parsing parameters for TRAP failed";
                if (trap_last_error_msg) {
                    err_msg += std::string(": ") + trap_last_error_msg;
                }
                throw std::runtime_error(err_msg);
            }

            trap_module_info_t module_info = {"FlowStoreStatsUnirec", "Output for ipfixprobe stats", 0, 1};
            m_trap_ctx = trap_ctx_init(&module_info, ifc_spec);
            if (m_trap_ctx == NULL) {
                throw std::runtime_error("Error: trap_ctx_init returned NULL.");
            }
            trap_free_ifc_spec(ifc_spec);
            m_unirec_ifc = 0;
        }
        trap_ctx_ifcctl(m_trap_ctx, TRAPIFC_OUTPUT, m_unirec_ifc, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
    }

    void GenerateTemplate(FlowStoreStat::Ptr ptr) {
        if(m_template) {
            return;
        }
        std::string time_tmpl = "time TIME,uint8 INSTANCE";

        // Create output template
        m_template = ur_create_template("", NULL);
        if (!m_template)
        {
            throw std::runtime_error("Error: ur_create_output_template returned NULL.");
        }

        /* Add TIME, INSTANCE Field */
        if (ur_define_set_of_fields(time_tmpl.c_str()) != UR_OK)
        {
           throw std::runtime_error("Error: Defining template fields failed.");
        }
        m_template = ur_expand_template(time_tmpl.c_str(), m_template);
        if(!m_template) {
            throw std::runtime_error("Error: Template generation failed: " + time_tmpl);
        }

        m_template = FlowStoreStatUnirecTemplate(m_template, ptr , "");

        int res = ur_ctx_set_output_template(m_trap_ctx, m_unirec_ifc, m_template);
        if(res != UR_OK) {
            throw std::runtime_error("Error: ur_ctx_set_output_template returned: " + std::to_string(res));
        }
    }

    void WriteStats(struct timeval current_ts, FlowStoreStat::Ptr ptr) {
        InitializeInterface();
        if(!m_trap_ctx) {
            return;
        }
        GenerateTemplate(ptr);
        if(!m_template) {
            throw std::runtime_error("Error: Template generation failed.");
        }
        if(!m_record) {
            m_record = ur_create_record(m_template, UR_MAX_SIZE);
            if(!m_record) {
                throw std::runtime_error("Error: ur_create_record returned NULL.");
            }
        }
        int field_id = ur_get_id_by_name("TIME");
        if(field_id == UR_E_INVALID_NAME) {
            throw std::runtime_error("Error: ur_get_id_by_name returned UR_E_INVALID_NAME.");
        }
        (*(ur_time_t *)ur_get_ptr_by_id(m_template, m_record, field_id)) = ur_time_from_sec_usec(current_ts.tv_sec, current_ts.tv_usec);

        field_id = ur_get_id_by_name("INSTANCE");
        if(field_id == UR_E_INVALID_NAME) {
            throw std::runtime_error("Error: ur_get_id_by_name returned UR_E_INVALID_NAME.");
        }
        (*(uint8_t *)ur_get_ptr_by_id(m_template, m_record, field_id)) = (uint8_t)m_instanceId;

        FlowStoreStatUnirec(m_template, m_record, ptr, "");
        int ret = trap_ctx_send(m_trap_ctx, m_unirec_ifc, m_record, ur_rec_size(m_template, m_record));
        TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, {goto write_end;}, {goto write_end;});
        trap_ctx_send_flush(m_trap_ctx, m_unirec_ifc);
write_end:
        if(ret) {
            std::cerr << "Trap send failed: " << ret;
        }
        return;
    }
};

template <typename FsParser>
class FlowStoreStatsUnirecParser : public FsParser {
public:
    std::string m_ifc_spec;

    FlowStoreStatsUnirecParser(const std::string &name = std::string("IFC Spec of ") + typeid(FsParser).name(), const std::string &desc = "") : FsParser(name, desc) {
        this->register_option("", "ifc", "ifc Spec", "Unirec interface to sent the data",
            [this](const char *arg){
                m_ifc_spec = std::string(arg);
                return true;
            },
            OptionsParser::RequiredArgument);
    }
};

template <typename F>
class FlowStoreStatsUnirec: public FlowStoreProxy<F, typename F::packet_info, typename F::accessor, typename F::iterator, FlowStoreStatsUnirecParser<typename F::parser>>
{
    typedef FlowStoreProxy<F, typename F::packet_info, typename F::accessor, typename F::iterator, FlowStoreStatsUnirecParser<typename F::parser>> Base;
public:

    typedef typename F::packet_info PacketInfo;
    typedef typename F::accessor Access;
    typedef typename F::iterator Iter;
    typedef FlowStoreStatsUnirecParser<typename F::parser> Parser;

    void init(Parser &parser) {
        m_unirec_writer.init(parser.m_ifc_spec);
        this->m_flowstore.init(parser);
    }
    FlowStoreStatsUnirec() : Base() {
    }
    ~FlowStoreStatsUnirec() {
        auto ptr = this->m_flowstore.stats_export();
        this->m_flowstore.stats_reset();
        m_unirec_writer.WriteStats(m_current_ts, ptr);
    }

    virtual PacketInfo prepare(Packet &pkt, bool inverse){
        m_current_ts = pkt.ts;
        return this->m_flowstore.prepare(pkt, inverse);
    }

    FlowStoreStat::Ptr stats_export() {
        auto ptr = this->m_flowstore.stats_export();

        this->m_flowstore.stats_reset();
        m_unirec_writer.WriteStats(m_current_ts, ptr);
        return ptr;
    };
private:
    struct timeval m_current_ts = { 0, 0 };
    FlowStoreStatsUnirecWriter m_unirec_writer;
};

}
#endif /* IPXP_FLOW_STORE_MONITOR_HPP */
