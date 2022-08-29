TEMPLATE = app
CONFIG += console c++14
CONFIG -= app_bundle
QMAKE_CXXFLAGS -= -Wunused-parameter
QMAKE_CFLAGS = -Wno-unused-parameter

INCLUDEPATH += ./include

SOURCES += \
        main.cpp \
        ./input/dpdk.cpp \
        ./input/ndp.cpp \
        ./input/nfbCInterface/ndpreader.cpp \
        ./input/stem.cpp \
        ./input/benchmark.cpp \
        ./input/parser.cpp \
        ./input/pcap.cpp \
        ./input/raw.cpp \
        ./main.cpp \
        ./options.cpp \
        ./output/ipfix-basiclist.cpp \
        ./output/text.cpp \
        ./output/unirec.cpp \
        ./output/ipfix.cpp \
        ./pluginmgr.cpp \
        ./process/basicplus.cpp \
        ./process/bstats.cpp \
        ./process/dns.cpp \
        ./process/dnssd.cpp \
        ./process/flexprobe-data-processing.cpp \
        ./process/flexprobe-encryption-processing.cpp \
        ./process/flexprobe-tcp-tracking.cpp \
        ./process/http.cpp \
        ./process/idpcontent.cpp \
        ./process/md5.cpp \
        ./process/netbios.cpp \
        ./process/ntp.cpp \
        ./process/ovpn.cpp \
        ./process/passivedns.cpp \
        ./process/phists.cpp \
        ./process/pstats.cpp \
        ./process/quic.cpp \
        ./process/rtsp.cpp \
        ./process/sip.cpp \
        ./process/smtp.cpp \
        ./process/stats.cpp \
        ./process/wg.cpp \
        ./process/ssdp.cpp \
        ./process/tls.cpp \
        ./process/last_pkt.cpp \
        ./stacktrace.cpp \
        ./storage/cache.cpp \
        ./storage/basic/flowcache.cpp \
        ./storage/basic/record.cpp \
        ./storage/basic/hashtablestore.cpp \
        ./storage/basic/flowcacheoutput.cpp \
        ./tests/unit/byte-utils.cpp \
        ./tests/unit/flowifc.cpp \
        ./tests/unit/options.cpp \
        ./tests/unit/skip.cpp \
        ./tests/unit/unirec.cpp \
        ./tests/unit/utils.cpp \
        ./utils.cpp \
        ./ipfixprobe.cpp \
        ./ipfixprobe_stats.cpp \
        ./stats.cpp \
        ./workers.cpp \

HEADERS += ./input/benchmark.hpp \
        ./input/headers.hpp \
        ./input/ndp.hpp \
        ./input/nfbCInterface/include/ndpreader.hpp \
        ./input/parser.hpp \
        ./input/raw.hpp \
        ./input/stem.hpp \
        ./input/pcap.hpp \
        ./output/ipfix.hpp \
        ./output/text.hpp \
        ./output/unirec.hpp \
        ./pluginmgr.hpp \
        ./process/basicplus.hpp \
        ./process/bstats.hpp \
        ./process/dns-utils.hpp \
        ./process/dns.hpp \
        ./process/dnssd.hpp \
        ./process/http.hpp \
        ./process/md5.hpp \
        ./process/netbios.hpp \
        ./process/ntp.hpp \
        ./process/ovpn.hpp \
        ./process/passivedns.hpp \
        ./process/phists.hpp \
        ./process/pstats.hpp \
        ./process/quic.hpp \
        ./process/rtsp.hpp \
        ./process/sip.hpp \
        ./process/smtp.hpp \
        ./process/ssdp.hpp \
        ./process/stats.hpp \
        ./process/wg.hpp \
        ./process/idpcontent.hpp \
        ./process/tls.hpp \
        ./process/last_pkt.hpp \
        ./stacktrace.hpp \
        ./storage/cache.hpp \
        ./storage/basic/flowcache.hpp \
        ./storage/basic/record.hpp \
        ./storage/basic/flowringbuffer.hpp \
        ./storage/basic/flowstore.hpp \
        ./storage/basic/hashtablestore.hpp \
        ./storage/basic/hiearchyflowstore.hpp \
        ./storage/basic/flowstoremonitor.hpp \
        ./storage/basic/flowstoreportfilter.hpp \
        ./storage/basic/flowstorestatswriter.hpp \
        ./storage/basic/flowstoreproxy.hpp \
        ./storage/basic/flowcacheoutput.hpp \
        ./storage/basic/hiearchyjoiniterator.hpp \
        storage/basic/cachedflowstore.hpp

