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
    std::cout << std::endl << "=====     Ethernet header   =====" << std::endl;
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
    std::cout << "===== end of Ethernet header =====" << std::endl << std::endl;
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
  std::string options;
  uint8_t ihl() const;
  size_t size() const;
  void dump() {
#ifdef MY_DEBUG
    std::cout << std::endl << "======   IPv4 header    =====" << std::endl;
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
    if (options.length() > 0) {
      std::cout << "options in hex: " << options << std::endl;
    }
    std::cout << "===== end of IPv4 header =====" << std::endl << std::endl;
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
  uint16_t payload_length;
  uint8_t next_header;
  uint8_t hop_limit;
  struct in6_addr src;
  struct in6_addr dst;
  void dump() {
#ifdef MY_DEBUG
    std::cout << std::endl << "===== IPv6 header =====" << std::endl;
    ::dump("version", version);
    ::dump("traffic_class", traffic_class);
    ::dump("flow_label", flow_label);
    ::dump("payload_length", payload_length);
    ::dump("next_header", next_header);
    ::dump("hop_limit", hop_limit);
    std::cout << "src_addr: " << std::hex << src.left << " " << src.right << std::endl;
    std::cout << "dst_addr: " << std::hex << dst.left << " " << dst.right << std::endl;
    std::cout << "===== end of IPv6 header =====" << std::endl << std::endl;
#endif
  }
};

class udp_header_t {
 public:
  port_t src_port;
  port_t dst_port;
  uint16_t length;
  uint16_t checksum;
  void dump() {
#ifdef MY_DEBUG
    std::cout << std::endl << "=====     UDP header    =====" << std::endl;
    std::cout << "src_port: " << src_port << std::endl;
    std::cout << "dst_port: " << dst_port << std::endl;
    std::cout << "length: " << length << std::endl;
    ::dump("checksum", checksum);
    std::cout << "===== end of UDP header =====" << std::endl << std::endl;
#endif
  }
};

class tcp_header_t {
 public:
  port_t src_port;
  port_t dst_port;
  uint32_t seq_num; /* sequence number */
  uint32_t ack_num; /* acknowledgment number */
  uint8_t
      hdr_size : 4,
      ns : 4;
  uint8_t flags; /* tcp flags */
  uint16_t win_size; /* window size */
  uint16_t checksum; /* checksum */
  uint16_t urg_ptr; /* urgent pointer */
  std::string options;
  bool cwr() const;
  bool ece() const;
  bool urg() const;
  bool ack() const;
  bool psh() const;
  bool rst() const;
  bool syn() const;
  bool fin() const;
  void dump() {
#ifdef MY_DEBUG
    std::cout << std::endl << "=====     TCP header    =====" << std::endl;
    std::cout << "src_port: " << src_port << std::endl;
    std::cout << "dst_port: " << dst_port << std::endl;
    ::dump("seq_num", seq_num);
    ::dump("ack_num", ack_num);
    ::dump("hdr_size", hdr_size);
    ::dump("ns", ns);
    ::dump("flags", flags);
    ::dump("win_size", win_size);
    ::dump("check_sum", checksum);
    ::dump("urg_ptr", urg_ptr);
    if (options.length() != 0) {
      std::cout << "options: " << options << std::endl;
    }
    std::cout << "===== end of TCP header =====" << std::endl << std::endl;
#endif
  }
  size_t size() const;
};

template<typename T>
T load(std::istream &stream, bool ntoh = true);

std::string to_string(const addr_t &addr);
std::string to_string(const in6_addr &addr);
}

#endif //DES_NET_H
