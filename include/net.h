//
// Created by aLIEzTed on 5/31/17.
//

#ifndef DES_NET_H
#define DES_NET_H
#include <iostream>
#include "helper.h"
namespace Net {
#define ETH_IPV4 0x0800
#define ETH_IPV6 0x86dd
#define ETH_ARP 0x0806

#define IP_UDP_PROTOCOL 0x11
#define IP_TCP_PROTOCOL 0x06
using addr_t = uint32_t;
using port_t = uint16_t;
struct ether_header_t {
  uint8_t dst_addr[6];
  uint8_t src_addr[6];
  uint16_t llc_len;

  void dump() {
#ifdef MY_DEBUG
    std::cout << "=====     Ethernet header   =====" << std::endl;
    std::cout << "dst MAC addr ";
    for (auto addr : dst_addr) {
      // dash it all
      std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << unsigned(addr) << " ";
    }
    std::cout << std::endl;
    std::cout << "src MAC addr ";
    for (auto addr : src_addr) {
      std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << unsigned(addr) << " ";
    }
    std::cout << std::endl;
    ::dump("llc_len", llc_len);
    std::cout << "===== end of Ethernet header =====" << std::endl;
#endif
  }
};

struct ipv4_header_t {
  uint8_t ver_ihl;  // 4 bits version and 4 bits internet header length
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  addr_t src_addr;
  addr_t dst_addr;
  void* options;
  uint8_t ihl() const;
  size_t size() const;
  void dump() {
#ifdef MY_DEBUG
    std::cout << "======   IP header    =====" << std::endl;
    ::dump("ver_ihl", ver_ihl);
    ::dump("tos", tos);
    ::dump("total_length", total_length);
    ::dump("id", id);
    ::dump("flags_to", flags_fo);
    ::dump("ttl", ttl);
    ::dump("protocol", protocol);
    ::dump("checksum", checksum);
    ::dump("src_addr", src_addr);
    ::dump("dst_addr", dst_addr);
    std::cout << "===== end of IP header =====" << std::endl;
#endif
  }

};

struct in6_addr {
  uint64_t left;
  uint64_t right;
};

struct ipv6_header_t {
  unsigned int
      version : 4,
      traffic_class : 8,
      flow_label : 20;
  uint16_t length;
  uint8_t next_header;
  uint8_t hop_limit;
  struct in6_addr src;
  struct in6_addr dst;
};

class udp_header_t {
 public:
  port_t src_port;
  port_t dst_port;
  uint16_t length;
  uint16_t checksum;
  void dump() {
#ifdef MY_DEBUG
    std::cout << "=====     UDP header    =====" << std::endl;
    std::cout << "src_port: " << src_port << std::endl;
    std::cout << "dst_port: " << dst_port << std::endl;
    std::cout << "length: " << length << std::endl;
    ::dump("checksum", checksum);
    std::cout << "===== end of UDP header =====" << std::endl;
#endif
  }
};

template<typename T>
T load(std::istream &stream, bool ntoh = true);

std::string to_string(const addr_t &addr);
}

#endif //DES_NET_H
