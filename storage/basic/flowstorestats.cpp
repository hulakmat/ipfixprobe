#include "flowstorestats.hpp"

#include <string>
#include <memory>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iostream>
#include <string>

#ifdef WITH_TRAP
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#endif

namespace ipxp {

FlowStoreStat::Ptr FlowStoreStatExpand(FlowStoreStat::Ptr ptr, FlowStoreStat::PtrVector expand) {
    if(ptr->getType() == FlowStoreStat::Array) {
        auto arr = ptr->getArray();
        std::move(expand.begin(), expand.end(), std::back_inserter(arr));
        return std::make_shared<FlowStoreStatVector>(ptr->getName(), arr);
    } else {
        expand.push_back(ptr);
        return std::make_shared<FlowStoreStatVector>(ptr->getName(), expand);
    }
}

void FlowStoreStatJSON(std::ostream &out, FlowStoreStat::Ptr ptr) {
    if(ptr->getType() == FlowStoreStat::Leaf) {
        out << "\"" << ptr->getName() << "\": " << ptr->getValue();
    } else {
        auto arr = ptr->getArray();
        if(!ptr->getName().empty()) {
            out << "\"" << ptr->getName() << "\" : ";
        }
        char startChar = '{';
        char endChar = '}';
        bool isArray = true;
        for(auto &i : arr ) {
            if(!i->getName().empty()) {
                isArray = false;
            }
        }
        if(isArray) {
            startChar = '[';
            endChar = ']';
        }

        if(arr.size() != 1) {
            out << startChar << std::endl;
        }
        for(auto &i : arr ) {
            FlowStoreStatJSON(out, i);
            if (&i != &arr.back()) {
                out << ",";
            }
            out << std::endl;
        }
        if(arr.size() != 1) {
            out << endChar << std::endl;
        }
    }
}


#ifdef WITH_TRAP

void FlowStoreStatUnirec(ur_template_t *tmpl, void *record, FlowStoreStat::Ptr ptr, std::string prefix)
{
    std::string name = prefix;
    if(!ptr->getName().empty()) {
        name = prefix + "_" + ptr->getName();
        if(prefix.empty()) {
            name = ptr->getName();
        }
    }
    std::replace(name.begin(), name.end(), ' ', '_');

    if(ptr->getType() == FlowStoreStat::Leaf) {
        std::string field_desc = name;
        int field_id = ur_get_id_by_name(field_desc.c_str());
        if(field_id == UR_E_INVALID_NAME) {
            throw std::runtime_error("Error: ur_get_id_by_name returned UR_E_INVALID_NAME.");
        }
        void *dPtr = ur_get_ptr_by_id(tmpl, record, field_id);
        if(!dPtr) {
            throw std::runtime_error("Error: ur_get_ptr_by_id returned NULL.");
        }
        ptr->setUnirecPtr(dPtr);
    } else {
        auto arr = ptr->getArray();
        for(auto &i : arr ) {
            FlowStoreStatUnirec(tmpl, record, i, name);
        }
    }
}

ur_template_t *FlowStoreStatUnirecTemplate(ur_template_t *tmpl, FlowStoreStat::Ptr ptr, std::string prefix)
{
    ur_template_t *out = tmpl;
    std::string name = prefix;
    if(!ptr->getName().empty()) {
        name = prefix + "_" + ptr->getName();
        if(prefix.empty()) {
            name = ptr->getName();
        }
    }
    std::replace(name.begin(), name.end(), ' ', '_');

    if(ptr->getType() == FlowStoreStat::Leaf) {
        std::string field_desc = ptr->getUnirecType() + " " + name;
        int res = ur_define_set_of_fields(field_desc.c_str());
        if(res != UR_OK) {
            throw std::runtime_error("Error: ur_define_set_of_fields returned " + std::to_string(res));
        }
        out = ur_expand_template(field_desc.c_str(), tmpl);
        if(!out) {
            throw std::runtime_error("Error: Template generation failed: " + field_desc);
        }
    } else {
        auto arr = ptr->getArray();
        for(auto &i : arr ) {
            out = FlowStoreStatUnirecTemplate(out, i, name);
        }
    }
    return out;
}
#endif

}
