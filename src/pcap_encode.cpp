//
// Created by aLIEzTed on 6/1/17.
//

#include "pcap_encode.h"
#include <fstream>
#include "net.h"
int PcapEncoder::read(const std::string filename) {
  std::ifstream in(filename, std::ios::binary);
  if (!in) {
    return FILE_NOT_FOUND;
  }
  auto pcap_file_header = read_pcap_file_header(in);
  pcap_file_header.dump();
  // TODO: read packet one by one and do filter
  auto packet = read_packet(in);
  std::cout << "data\n" << packet.data << std::endl;
  packet = read_packet(in);
  in.close();
  return 0;
}

PcapEncoder::pcap_hdr_t PcapEncoder::read_pcap_file_header(std::istream &stream) {
  pcap_hdr_t header;
  stream.read((char *) &header.magic_number, sizeof(header.magic_number));
  stream.read((char *) &header.version_major, sizeof(header.version_major));
  stream.read((char *) &header.version_minor, sizeof(header.version_minor));
  stream.read((char *) &header.thiszone, sizeof(header.thiszone));
  stream.read((char *) &header.sigfigs, sizeof(header.sigfigs));
  stream.read((char *) &header.snaplen, sizeof(header.snaplen));
  stream.read((char *) &header.network, sizeof(header.network));
  return header;
}

PcapEncoder::pcaprec_hdr_t PcapEncoder::read_pcap_packet_header(std::istream &stream) {
  pcaprec_hdr_t header;
  stream.read((char *) &header.ts_sec, sizeof(header.ts_sec));
  stream.read((char *) &header.ts_usec, sizeof(header.ts_usec));
  stream.read((char *) &header.incl_len, sizeof(header.incl_len));
  stream.read((char *) &header.orig_len, sizeof(header.orig_len));
  return header;
}

PcapEncoder::Packet PcapEncoder::read_packet(std::istream &stream) {
  // TODO: implement reading into a packet.
  pcaprec_hdr_t packet_hdr = read_pcap_packet_header(stream);
  packet_hdr.dump();
  Packet packet;
  packet.hdr = packet_hdr;
  Net::ether_header_t eth_hdr = Net::load<Net::ether_header_t>(stream);
  eth_hdr.dump();

  if (eth_hdr.llc_len == ETH_IPV4) {
    // ipv4 in network layer
    Net::ipv4_header_t ipv4_hdr = Net::load<Net::ipv4_header_t>(stream);
    ipv4_hdr.dump();
    if (ipv4_hdr.protocol == IP_TCP_PROTOCOL) {
      // tcp protocol
      // TODO: compose TCP packet as course spec
    } else if (ipv4_hdr.protocol == IP_UDP_PROTOCOL) {
      // udp protocol
      Net::udp_header_t udp_hdr = Net::load<Net::udp_header_t>(stream);
      udp_hdr.dump();
      // TODO: compose UDP packet as course spec
      // udp data size in bytes
      auto bytes = udp_hdr.length - 8;
      char* data = new char[bytes];
      stream.read(data, bytes);
      packet.data = data;
    } else {
      // other transmission layer protocol, ignore them
    }
  } else if (eth_hdr.llc_len == ETH_IPV6) {
    Net::ipv6_header_t ipv6_hdr = Net::load<Net::ipv6_header_t>(stream);
  } else {
    // other network layer protocol, ignore them
  }


  return packet;
}