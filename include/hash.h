//
// Created by aLIEzTed on 6/3/17.
//

#ifndef DES_HASH_H
#define DES_HASH_H
#include "pcap_encode.h"
namespace std {
template<>
struct hash<PcapEncoder::Packet> {
  size_t operator()(PcapEncoder::Packet const &s) const {
    size_t const h1(std::hash<std::string>{}(s.src_addr));
    size_t const h2(std::hash<std::string>{}(s.dst_addr));
    size_t const h3(std::hash<uint16_t>{}(s.src_port));
    size_t const h4(std::hash<uint16_t>{}(s.dst_port));
    size_t result(0);
    result = 37 * result + h1;
    result = 37 * result + h2;
    result = 37 * result + h3;
    result = 37 * result + h4;
    return result;
  }
};

}
#endif //DES_HASH_H
