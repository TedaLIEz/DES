//
// Created by aLIEzTed on 6/1/17.
//

#include "pcap_encode.h"
#include <fstream>
#include <assert.h>
#include "net.h"
int PcapEncoder::read(const std::string filename) {
  std::ifstream in(filename, std::ios::binary);
  if (!in) {
    return FILE_NOT_FOUND;
  }
  auto pcap_file_header = read_pcap_file_header(in);
  pcap_file_header.dump();
  // TODO: read packet one by one and do filter
  int packet_size = 1;
  while (in.peek() != EOF) {
    auto p = read_packet(in);
    if (p.type != pType::OTHERS) {
      std::cout << "packet " << packet_size << std::endl;
      p.dump();
    }
    packet_size++;
  }
  // we have a end of line here
  assert(in.eof());
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

std::string PcapEncoder::read_data(std::istream &stream, int size) {
#ifdef MY_DEBUG
  std::cout << "data size " << size << std::endl;
#endif
  char *buffer = new char[size];
  stream.read(buffer, size);
  auto rst = convert_data(buffer, size);
  delete[] buffer;
  return rst;
}

PcapEncoder::Packet PcapEncoder::read_packet(std::istream &stream) {
  // TODO: implement reading data into a packet struct.
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
    packet.src_addr = Net::to_string(ipv4_hdr.src_addr);
    packet.dst_addr = Net::to_string(ipv4_hdr.dst_addr);
    if (ipv4_hdr.protocol == IP_TCP_PROTOCOL) {
      // tcp protocol
      Net::tcp_header_t tcp_hdr = Net::load<Net::tcp_header_t>(stream);
      tcp_hdr.dump();
      auto bytes = ipv4_hdr.total_length - tcp_hdr.size() - ipv4_hdr.size();
      auto padding = packet_hdr.incl_len - sizeof(eth_hdr) - ipv4_hdr.size() - tcp_hdr.size() - bytes;
      // we have padding in ethernet frame,
      // see http://forums.devshed.com/networking-help-109/tcp-protocol-mysterious-6-null-byte-payload-303357.html
      // and https://stackoverflow.com/a/23998612/4380801
#ifdef MY_DEBUG
      std::cout << "padding " << padding << std::endl;
#endif
      packet.data = read_data(stream, (int) bytes);
      packet.src_port = tcp_hdr.src_port;
      packet.dst_port = tcp_hdr.dst_port;
      stream.seekg(padding, stream.cur);
      packet.type = pType::TCP;
    } else if (ipv4_hdr.protocol == IP_UDP_PROTOCOL) {
      // udp protocol
      Net::udp_header_t udp_hdr = Net::load<Net::udp_header_t>(stream);
      udp_hdr.dump();
      // udp data size in bytes
      auto bytes = udp_hdr.length - 8;
      // currently we read data into string in hex
      packet.data = read_data(stream, bytes);
      packet.src_port = udp_hdr.src_port;
      packet.dst_port = udp_hdr.dst_port;
      packet.type = pType::UDP;
    } else {
      // other transmission layer protocol, ignore them

      stream.seekg(packet_hdr.incl_len - sizeof(eth_hdr) - ipv4_hdr.size(), stream.cur);
    }
  } else if (eth_hdr.llc_len == ETH_IPV6) {
    Net::ipv6_header_t ipv6_hdr = Net::load<Net::ipv6_header_t>(stream);
    ipv6_hdr.dump();
    packet.src_addr = Net::to_string(ipv6_hdr.src);
    packet.dst_addr = Net::to_string(ipv6_hdr.dst);
    if (ipv6_hdr.next_header == IP_TCP_PROTOCOL) {
      Net::tcp_header_t tcp_hdr = Net::load<Net::tcp_header_t>(stream);
      tcp_hdr.dump();
      auto bytes = ipv6_hdr.payload_length - tcp_hdr.size();
      packet.data = read_data(stream, (int) bytes);
      packet.src_port = tcp_hdr.src_port;
      packet.dst_port = tcp_hdr.dst_port;
      packet.type = pType::TCP;
    } else if (ipv6_hdr.next_header == IP_UDP_PROTOCOL) {
      Net::udp_header_t udp_hdr = Net::load<Net::udp_header_t>(stream);
      udp_hdr.dump();
      // udp data size in bytes
      auto bytes = udp_hdr.length - 8;
      // currently we read data into string in hex
      packet.data = read_data(stream, bytes);
      packet.src_port = udp_hdr.src_port;
      packet.dst_port = udp_hdr.dst_port;
      packet.type = pType::UDP;
    } else {
      // other transmission layer protocol, ignore them
      stream.seekg(packet_hdr.incl_len - sizeof(ipv6_hdr) - sizeof(eth_hdr), stream.cur);
    }
  } else {
    packet.type = pType::OTHERS;
    stream.seekg(packet_hdr.incl_len - sizeof(eth_hdr), stream.cur);
    // other network layer protocol, ignore them
#ifdef MY_DEBUG
    std::cout << "other network layer protocol, ignore " << std::endl << std::endl;
#endif
  }

  return packet;
}

std::string PcapEncoder::convert_data(char *buffer, int size) const {
  std::stringstream ss;
  for (int i = 0; i < size; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << unsigned((uint8_t) buffer[i]);
  }
  std::string mystr = ss.str();
  return mystr;
}