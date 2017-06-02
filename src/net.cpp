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
  auto size = header.size();
  if (size > 160) {
    char* data = new char[size / 8];
    stream.read(data, size / 8);
    header.options = data;
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
//  char* tmp = new char[1];
//  stream.read(tmp, 1);
//  unsigned int t = *tmp;
//  header.version = t >>
//  stream.read((char*) &header.version, 1);

  return header;
}

uint8_t ipv4_header_t::ihl() const {
  return (ver_ihl & 0x0F);
}

size_t ipv4_header_t::size() const {
  return ihl() * sizeof(uint32_t);
}


}