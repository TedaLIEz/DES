//
// Created by aLIEzTed on 5/31/17.
//

#include "net.h"
namespace Net {

template<>
ether_header_t load(std::istream &stream, bool ntoh) {
  ether_header_t header;
  stream.read((char *) header.dst_addr, 6 * sizeof(header.dst_addr[0]));
  stream.read((char *) header.src_addr, 6 * sizeof(header.src_addr[0]));
  stream.read((char *) &header.llc_len, sizeof(header.llc_len));
  if (ntoh) {
    header.llc_len = ntohs(header.llc_len);
  }
  return header;
}

template<>
ipv4_header_t load(std::istream &stream, bool ntoh) {
  ipv4_header_t header;
  stream.read((char *) &header.ver_ihl, sizeof(header.ver_ihl));
  stream.read((char *) &header.tos, sizeof(header.tos));
  stream.read((char *) &header.total_length, sizeof(header.total_length));
  stream.read((char *) &header.id, sizeof(header.id));
  stream.read((char *) &header.flags_fo, sizeof(header.flags_fo));
  stream.read((char *) &header.ttl, sizeof(header.ttl));
  stream.read((char *) &header.protocol, sizeof(header.protocol));
  stream.read((char *) &header.checksum, sizeof(header.checksum));
  stream.read((char *) &header.src_addr, sizeof(header.src_addr));
  stream.read((char *) &header.dst_addr, sizeof(header.dst_addr));
  if (ntoh) {
    header.total_length = ntohs(header.total_length);
    header.id = ntohs(header.id);
    header.flags_fo = ntohs(header.flags_fo);
    header.checksum = ntohs(header.checksum);
    header.src_addr = ntohl(header.src_addr);
    header.dst_addr = ntohl(header.dst_addr);
  }

  // TODO: deal with options in ipv4_header, review is needed
  if (header.ihl() > 5) {
    auto options = (header.ihl() - 5) * sizeof(uint32_t);
    char *buffer = new char[options];
    stream.read(buffer, options);
    std::stringstream ss;
    for (int i = 0; i < options; ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0') << unsigned((uint8_t) buffer[i]);
    }
    std::string mystr = ss.str();
    header.options = mystr;
  }
  return header;
}

template<>
udp_header_t load(std::istream &stream, bool ntoh) {
  udp_header_t header;
  stream.read((char *) &header.src_port, sizeof(header.src_port));
  stream.read((char *) &header.dst_port, sizeof(header.dst_port));
  stream.read((char *) &header.length, sizeof(header.length));
  stream.read((char *) &header.checksum, sizeof(header.checksum));
  if (ntoh) {
    header.src_port = ntohs(header.src_port);
    header.dst_port = ntohs(header.dst_port);
    header.length = ntohs(header.length);
    header.checksum = ntohs(header.checksum);
  }
  return header;
}

template<>
ipv6_header_t load(std::istream &stream, bool ntoh) {
  ipv6_header_t header;
  uint32_t v_t(0);
  stream.read((char *) &v_t, 4);
  if (ntoh) {
    v_t = ntohl(v_t);
  }
  header.version = (v_t >> 28);
  header.traffic_class = (v_t & 0x0FFFFFFF) >> 24;
  header.flow_label = (v_t & 0x000FFFFF);
  stream.read((char *) &header.payload_length, sizeof(header.payload_length));
  stream.read((char *) &header.next_header, sizeof(header.next_header));
  stream.read((char *) &header.hop_limit, sizeof(header.hop_limit));
  // TODO: review code
  uint64_t tmp(0);
  stream.read((char *) &tmp, 8);
  header.src.left = tmp;
  stream.read((char *) &tmp, 8);
  header.src.right = tmp;
  stream.read((char *) &tmp, 8);
  header.dst.left = tmp;
  stream.read((char *) &tmp, 8);
  header.dst.right = tmp;
  if (ntoh) {
    header.payload_length = ntohs(header.payload_length);
    header.src.left = ntohll(header.src.left);
    header.src.right = ntohll(header.src.right);
    header.dst.left = ntohll(header.dst.left);
    header.dst.right = ntohll(header.dst.right);
  }
  return header;
}

uint8_t ipv4_header_t::ihl() const {
  return (ver_ihl & 0x0F);
}

size_t ipv4_header_t::size() const {
  return ihl() * sizeof(uint32_t);
}

template<>
tcp_header_t load(std::istream &stream, bool ntoh) {
  tcp_header_t header;
  stream.read((char *) &header.src_port, sizeof(header.src_port));
  stream.read((char *) &header.dst_port, sizeof(header.dst_port));
  stream.read((char *) &header.seq_num, sizeof(header.seq_num));
  stream.read((char *) &header.ack_num, sizeof(header.ack_num));
  uint8_t t;
  stream.read((char *) &t, sizeof(t));
  header.hdr_size = t >> 4;
  header.ns = (uint8_t) (t & 0x0F);
  stream.read((char *) &header.flags, sizeof(header.flags));
  stream.read((char *) &header.win_size, sizeof(header.win_size));
  stream.read((char *) &header.checksum, sizeof(header.checksum));
  stream.read((char *) &header.urg_ptr, sizeof(header.urg_ptr));
  if (ntoh) {
    header.src_port = ntohs(header.src_port);
    header.dst_port = ntohs(header.dst_port);
    header.seq_num = ntohl(header.seq_num);
    header.ack_num = ntohl(header.ack_num);
    header.win_size = ntohs(header.win_size);
    header.checksum = ntohs(header.checksum);
    header.urg_ptr = ntohs(header.urg_ptr);
  }
  if (header.hdr_size > 5) {
    // we have options in header
    auto options = (header.hdr_size - 5) * sizeof(uint32_t);
    char *buffer = new char[options];
    stream.read(buffer, options);
    std::stringstream ss;
    for (int i = 0; i < options; ++i) {
      ss << std::hex << std::setw(2) << std::setfill('0') << unsigned((uint8_t) buffer[i]);
    }
    std::string mystr = ss.str();
    header.options = mystr;
  }
  return header;
}

size_t tcp_header_t::size() const {
  return hdr_size * sizeof(uint32_t);
}

bool tcp_header_t::ack() const {
  return (flags & 0x10) == 1;
}

bool tcp_header_t::cwr() const {
  return (flags & 0x80) == 1;
}

bool tcp_header_t::ece() const {
  return (flags & 0x40) == 1;
}

bool tcp_header_t::fin() const {
  return (flags & 0x01) == 1;
}

bool tcp_header_t::rst() const {
  return (flags & 0x04) == 1;
}

bool tcp_header_t::syn() const {
  return (flags & 0x02) == 1;
}

bool tcp_header_t::psh() const {
  return (flags & 0x04) == 1;
}

bool tcp_header_t::urg() const {
  return (flags & 0x20) == 1;
}

std::string to_string(const addr_t &addr) {
  auto ip1 = addr & 0xFF;
  auto ip2 = (addr >> 8) & 0xFF;
  auto ip3 = (addr >> 16) & 0xFF;
  auto ip4 = (addr >> 24) & 0xFF;
  std::stringstream ss;
  ss << ip4 << "." << ip3 << "." << ip2 << "." << ip1;
  return ss.str();

}

std::string to_string(const in6_addr &addr) {
  std::stringstream ss;
  auto ip8 = addr.right & 0xFFFF;
  auto ip7 = (addr.right >> 16) & 0xFFFF;
  auto ip6 = (addr.right >> 32) & 0xFFFF;
  auto ip5 = (addr.right >> 48) & 0xFFFF;
  auto ip4 = (addr.left & 0xFFFF);
  auto ip3 = (addr.left >> 16) & 0xFFFF;
  auto ip2 = (addr.left >> 32) & 0xFFFF;
  auto ip1 = (addr.left >> 48) & 0xFFFF;
  ss << std::hex << std::setw(4) << std::setfill('0') <<
  ip1 << "." << ip2 << "." << ip3 << "." << ip4 << "." << ip5 << "." << ip6 << "." << ip7 << "." << ip8;
  return ss.str();
}

}