#ifndef IPXP_INDEXER_HPP
#define IPXP_INDEXER_HPP

#include <mutex>
#include <cmath>
#include <queue>
#include <thread>
#include <condition_variable>
#include <ipfixprobe/input.hpp>

//#define INDEXER_DEBUG_ENABLE
//#define INDEXER_QUEUE_DEBUG_ENABLE

#ifdef INDEXER_DEBUG_ENABLE
#define INDEXER_DEBUG(x) std::cerr << x << std::endl;
#else
#define INDEXER_DEBUG(x)
#endif

#ifdef INDEXER_QUEUE_DEBUG_ENABLE
#define INDEXER_QUEUE_DEBUG(x) std::cerr << x << std::endl;
#else
#define INDEXER_QUEUE_DEBUG(x)
#endif

namespace ipxp {

template<typename T>
class ConcurrentQueue
{
public:
    ConcurrentQueue() {
        INDEXER_QUEUE_DEBUG("ConcurrentQueue Constructed: " << this);
    }
    
    void push(T const& v)
    {
        INDEXER_QUEUE_DEBUG("ConcurrentQueue Pushing element");
        {
            std::unique_lock<std::mutex> lock(the_mutex);
            the_queue.push(v);
        }
        the_condition_variable.notify_one();
    }
    
    void wait_element()
    {
        std::unique_lock<std::mutex> lock(the_mutex);
        if(the_queue.empty()) {
            INDEXER_QUEUE_DEBUG("ConcurrentQueue Waiting");
        }
        while (the_queue.empty() && !stopped)
            the_condition_variable.wait(lock);
    }
    
    bool empty() const
    {
        std::unique_lock<std::mutex> lock(the_mutex);
        return the_queue.empty();
    }
    
    T& front() {
        std::unique_lock<std::mutex> lock(the_mutex);
        return the_queue.front();
    }
    
    T& wait_and_pop()
    {
        std::unique_lock<std::mutex> lock(the_mutex);
        while (the_queue.empty())
            the_condition_variable.wait(lock);
        T& popped_value = the_queue.front();
        the_queue.pop();
        return popped_value;
    }
    
    void pop() {
        INDEXER_QUEUE_DEBUG("ConcurrentQueue Poping element");
        std::unique_lock<std::mutex> lock(the_mutex);
        the_queue.pop();
    }
    
    void stop() {
        INDEXER_QUEUE_DEBUG("ConcurrentQueue stopped");
        stopped = true;
        the_condition_variable.notify_all();
    }
    
    bool is_stopped() const {
        return stopped;
    }
    
private:
    bool stopped = false;
    std::queue<T> the_queue;
    mutable std::mutex the_mutex;
    std::condition_variable the_condition_variable;
};
typedef ConcurrentQueue<Packet*> PacketQueue;
typedef std::tuple<Packet*, PacketQueue*> PacketIndexerStruct;
typedef ConcurrentQueue<PacketIndexerStruct> PacketIndexerQueue;

class ThreadRunner
{
public:
    virtual ~ThreadRunner() {}
    void start() {
        INDEXER_DEBUG("Starting: " << this->name());
        m_thread = std::thread(&ThreadRunner::run, this);
    }
    
    void join() {
        INDEXER_DEBUG("Joining: " << this->name());
        m_thread.join();
        INDEXER_DEBUG("Joined: " << this->name());
    }
    
    void run() {
        INDEXER_DEBUG("Running: " << this->name());
        running = true;
        while(running) {
            process();
        }
        INDEXER_DEBUG("Stopped: " << this->name());
    }
    
    void stop() {
        INDEXER_DEBUG("Stopping: " << this->name());
        running = false;
    }
    
    virtual const char* name() {
        return "ThreadRunner";
    }
    
protected:
    virtual void process() {}
    bool running = true;
    
private:
    std::thread m_thread;
};

class ThreadPacketIndexerInner : public ThreadRunner
{
public:
    ThreadPacketIndexerInner(PacketIndexerQueue *inputQueue) : input(inputQueue) {
        INDEXER_DEBUG("Indexer input: " << inputQueue);
    }
    
    void process()
    {
        input->wait_element();
        if(!this->running) {
            return;
        }
        auto pktStr = input->front();
        input->pop();
        auto pkt = std::get<0>(pktStr);
        auto queue = std::get<1>(pktStr);
        INDEXER_DEBUG("Indexer Pushing packet: " << pkt<< " index: " << index << " into: " << queue);
        pkt->link_index = index++;
        queue->push(pkt);
    }
    
    void stop() {
        input->stop();
        ThreadRunner::stop();
    }
    
    const char* name() {
        return "ThreadPacketIndexerInner";
    }
private:
    uint64_t index = 0;
    PacketIndexerQueue *input;
};


typedef std::tuple<PacketIndexerStruct, PacketIndexerQueue*> PacketIndexerStructLocalMinStruct;
bool IndexLocalMinCMP(const PacketIndexerStructLocalMinStruct& a, const PacketIndexerStructLocalMinStruct& b);

class ThreadPacketSorterInner : public ThreadRunner
{
public:
    ThreadPacketSorterInner(std::vector<PacketIndexerQueue*> inputs, PacketIndexerQueue* output) : inputQueues(inputs), output(output) {
        INDEXER_DEBUG("Inputs len: " << inputs.size());
        for(auto i : inputs) {
            INDEXER_DEBUG(" - " << i);
        }
        INDEXER_DEBUG("Output - " << output);
    }
    
    void process() {
        /* Wait for all inputs */
        for(auto &i : inputQueues) {
            i->wait_element();
        }
        if(!this->running) {
            return;
        }
        
        std::vector<PacketIndexerStructLocalMinStruct> localMin;
        for(auto &i : inputQueues) {
            localMin.push_back(PacketIndexerStructLocalMinStruct(i->front(), i));
        }
        auto min = *(std::min_element(localMin.begin(), localMin.end(), IndexLocalMinCMP));
        auto queue = std::get<1>(min);
        
        queue->wait_element();
        if(!this->running) {
            return;
        }
        
        INDEXER_DEBUG("Pushing into: " << queue);
        output->push(queue->front());
        queue->pop();
    }
    
    void stop() {
        for(auto i : inputQueues) {
            i->stop();
        }
        ThreadRunner::stop();
    }
    
    const char* name() {
        return "ThreadPacketSorterInner";
    }
    
private:
    std::vector<PacketIndexerQueue*> inputQueues;
    PacketIndexerQueue *output;
};

class ThreadPacketIndexer : public ThreadRunner
{
public:
    static ThreadPacketIndexer *GetInstance() {
        return _singleton;
    }
    
    ThreadPacketIndexer(size_t ins, size_t procs) {
        INDEXER_DEBUG("Packet Indexer inputs: " << ins << " procs: " << ins);
        if(ins == 0) {
            return;
        }
        
        _singleton = this;
        size_t depth = std::log(ins)/std::log(procs);
        
        for(size_t i = 0; i < ins; i++) {
            inputs.push_back(new PacketIndexerQueue());
        }
        
        std::vector<PacketIndexerQueue*> currentInputs = inputs;
        std::vector<PacketIndexerQueue*> nextInputs;
        for(size_t i = 0; i < depth; i++) {
            for(size_t z = 0; z < currentInputs.size()/procs; z++) {
                INDEXER_DEBUG("Packet Indexer create depth: " << i << " ind: " << z);
                auto oQ = new PacketIndexerQueue();
                inputs.push_back(oQ);
                nextInputs.push_back(oQ);
                
                size_t startInd = z*procs;
                size_t endInd = (z+1)*procs;
                INDEXER_DEBUG("Inputs Size: " << currentInputs.size() << " Slice Indexes: " << z*procs << ":" << startInd << " - " <<  endInd - startInd);
                auto sortInputs = std::vector<PacketIndexerQueue*>(currentInputs.begin()+startInd, currentInputs.begin()+endInd);
                auto sorter = new ThreadPacketSorterInner(sortInputs, oQ);
                sorters.push_back(sorter);
            }
            currentInputs = nextInputs;
        }
        
        /* Should be one */
        auto indexInputQueue = currentInputs.front();
        indexer = new ThreadPacketIndexerInner(indexInputQueue);
    }
    
    ~ThreadPacketIndexer() {
        for(auto i : inputs) {
            delete i;
        }
        for(auto s : sorters) {
            delete s;
        }
        delete indexer;
    }
    
    void start() {
        if(!indexer) return;
        for(auto s : sorters) {
            s->start();
        }
        indexer->start();
    }
    
    void stop() {
        if(!indexer) return;
        for(auto s : sorters) {
            s->stop();
        }
        indexer->stop();
    }
    
    void join() {
        if(!indexer) return;
        for(auto s : sorters) {
            s->join();
        }
        indexer->join();
    }
    
    PacketIndexerQueue* get_input(int index) {
        return inputs[index];
    }
    
private:
    static ThreadPacketIndexer *_singleton;
    std::vector<PacketIndexerQueue*> inputs;
    std::vector<ThreadPacketSorterInner*> sorters;
    ThreadPacketIndexerInner *indexer;
};
}

#endif
