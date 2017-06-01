//
// Created by aLIEzTed on 5/31/17.
//

#ifndef DES_NET_H
#define DES_NET_H

namespace Net {

using addr_t = uint32_t;
using port_t = uint16_t;

struct ether_header_t {
  uint8_t dst_addr[6];
  uing8_t src_addr[6];
  uint16_t llc_len;
};

struct ip_header_t {
  uint8_t ver_ihl;         /* 4 bits version and 4 bits internet header length */
  uint8_t tos;
  uint8_t total_length;
  uint16_t id;
  uint16_t flags_fo;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  addr_t src_addr;
  addr_t dst_addr;
  uint8_t ihl() const;
  size_t size() const;
};

class udp_header_t {
 public:
  port_t src_port;
  port_t dst_port;
  uint16_t length;
  uint16_t checksum;
};


template<typename T>
T load(std::istream &stream, bool noth = true);
template<>
ip_header_t load(std::istream &stream, bool ntoh);
template<>
udp_header_t load(std::istream &stream, bool ntoh);

std::string to_string(const addr_t &addr);

}

#endif //DES_NET_H
