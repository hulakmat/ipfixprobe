#include "flowstorestats.hpp"

#include <string>
#include <memory>
#include <sstream>
#include <vector>

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
            out << ptr->getName() << " : ";
        }
        if(arr.size() != 1) {
            out << "{" << std::endl;
        }
        for(auto &i : arr ) {
            FlowStoreStatJSON(out, i);
            if (&i != &arr.back()) {
                out << ",";
            }
            out << std::endl;
        }
        if(arr.size() != 1) {
            out << "}" << std::endl;
        }
    }
}

}