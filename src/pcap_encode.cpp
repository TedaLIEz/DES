//
// Created by aLIEzTed on 6/1/17.
//

#include "pcap_encode.h"
#include <fstream>
#include <assert.h>
#include "net.h"
#include "hash.h"
#include "io.h"
int PcapEncoder::analyze_pcap(const std::string filename) {
  std::ifstream in(filename, std::ios::binary);
  if (!in) {
    return FILE_NOT_FOUND;
  }
  pcap_hdr = read_pcap_file_header(in);
  pcap_hdr.dump();
  // TODO: read packet one by one and do filter
  while (in.peek() != EOF) {
    auto p = read_packet(in);
    p.dump();
    filter(p);
  }

  assemble();
  save_to_pcap();

  // we have a end of line here
  assert(in.eof());
  in.close();
  return 0;
}

void PcapEncoder::assemble() {
}

void PcapEncoder::filter(Packet &packet) {
  if (packet.type == pType::UDP) {
    reassemble_udp_packet(packet);
  } else if (packet.type == pType::TCP) {
    reassemble_tcp_packet(packet);
  }
}

void PcapEncoder::save_to_pcap() {
  IO::pcap::save_pcap("UDP", pcap_hdr, udp_map);
  IO::pcap::save_pcap("TCP", pcap_hdr, tcp_map);


}

void PcapEncoder::save_to_txt() {
  // TODO: save to tcp packet
  IO::txt::save_udp_txt(udp_map);
}

void PcapEncoder::reassemble_tcp_packet(Packet &packet) {
  auto it = tcp_map.find(packet.hashcode);
  if (it == tcp_map.end()) {
    tcp_map[packet.hashcode] = std::vector<Packet>();
  }
  std::vector<Packet> *v = &tcp_map[packet.hashcode];
  if (v->empty()) {
    v->push_back(packet);
  }
  if (v->back().dst_addr == packet.dst_addr) {
    if (v->back().seq_num + v->back().data_len <= packet.seq_num) {
      v->push_back(packet);
    } else {
      for (int i = (int) (v->size() - 2); i >= 0; i--) {
        if ((*v)[i].dst_addr == packet.dst_addr
            && (*v)[i].seq_num + (*v)[i].data_len <= packet.seq_num) {
          v->insert(v->begin() + i + 1, packet);
          break;
        }
      }
    }
  } else {
    if (v->back().ack_num == packet.ack_num) {
      v->push_back(packet);
    }
  }

}
void PcapEncoder::reassemble_udp_packet(Packet &packet) {
  auto it = udp_map.find(packet.hashcode);
  if (it != udp_map.end()) {
    auto bound = std::lower_bound(udp_map[packet.hashcode].begin(), udp_map[packet.hashcode].end(), packet);
    if (bound != udp_map[packet.hashcode].end()) {
      udp_map[packet.hashcode].insert(bound, packet);
    } else {
      udp_map[packet.hashcode].push_back(packet);
    }
  } else {
    udp_map.insert(std::pair<size_t, std::vector<Packet>>(packet.hashcode, std::vector<Packet>()));
    udp_map[packet.hashcode].push_back(packet);
  }
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

void PcapEncoder::read_data(std::istream &stream, size_t size, char* buffer) {
#ifdef MY_DEBUG
  std::cout << "data size " << size << std::endl;
#endif
  stream.read(buffer, size);
}

PcapEncoder::Packet PcapEncoder::read_packet(std::istream &stream) {
  auto curpos = stream.tellg();
  pcaprec_hdr_t packet_hdr = read_pcap_packet_header(stream);
  auto packet_len = packet_hdr.orig_len;
  stream.seekg(curpos);
  Packet packet;
  packet.ori_len = sizeof(packet_hdr) + packet_len;
  packet.ori_data = new char[packet_len + sizeof(packet_hdr)];
  read_data(stream, packet_len + sizeof(packet_hdr), packet.ori_data);
  stream.seekg(curpos + (std::fpos<mbstate_t>) sizeof(packet_hdr));
  packet.ts = packet_hdr.ts_sec + packet_hdr.ts_usec;
  Net::ether_header_t eth_hdr = Net::load<Net::ether_header_t>(stream);

  if (eth_hdr.llc_len == ETH_IPV4) {
    // ipv4 in network layer
    Net::ipv4_header_t ipv4_hdr = Net::load<Net::ipv4_header_t>(stream);
    packet.src_addr = Net::to_string(ipv4_hdr.src_addr);
    packet.dst_addr = Net::to_string(ipv4_hdr.dst_addr);
    if (ipv4_hdr.protocol == IP_TCP_PROTOCOL) {
      // tcp protocol
      Net::tcp_header_t tcp_hdr = Net::load<Net::tcp_header_t>(stream);
      auto bytes = ipv4_hdr.total_length - tcp_hdr.size() - ipv4_hdr.size();
      auto padding = packet_hdr.incl_len - sizeof(eth_hdr) - ipv4_hdr.size() - tcp_hdr.size() - bytes;
      // we have padding in ethernet frame,
      // see http://forums.devshed.com/networking-help-109/tcp-protocol-mysterious-6-null-byte-payload-303357.html
      // and https://stackoverflow.com/a/23998612/4380801
#ifdef MY_DEBUG
      std::cout << "padding " << padding << std::endl;
#endif
      packet.data_len = bytes;

      packet.type = pType::TCP;
      packet.data = new char[bytes];
      read_data(stream, bytes, packet.data);
      packet.seq_num = tcp_hdr.seq_num;
      packet.ack_num = tcp_hdr.ack_num;
      packet.src_port = tcp_hdr.src_port;
      packet.dst_port = tcp_hdr.dst_port;
      packet.hashcode = std::hash<Packet>{}(packet);
      stream.seekg(padding, stream.cur);
    } else if (ipv4_hdr.protocol == IP_UDP_PROTOCOL) {
      // udp protocol
      Net::udp_header_t udp_hdr = Net::load<Net::udp_header_t>(stream);
      // udp data size in bytes
      size_t bytes = (size_t) (udp_hdr.length - 8);
      // currently we read data into string in hex
      packet.data_len = bytes;
      packet.data = new char[bytes];
      read_data(stream, bytes, packet.data);
      packet.src_port = udp_hdr.src_port;
      packet.dst_port = udp_hdr.dst_port;
      packet.hashcode = std::hash<Packet>{}(packet);
      packet.type = pType::UDP;
    } else {
      // other transmission layer protocol, ignore them
      stream.seekg(packet_hdr.incl_len - sizeof(eth_hdr) - ipv4_hdr.size(), stream.cur);
    }
  } else if (eth_hdr.llc_len == ETH_IPV6) {
    Net::ipv6_header_t ipv6_hdr = Net::load<Net::ipv6_header_t>(stream);
    packet.src_addr = Net::to_string(ipv6_hdr.src);
    packet.dst_addr = Net::to_string(ipv6_hdr.dst);
    if (ipv6_hdr.next_header == IP_TCP_PROTOCOL) {
      Net::tcp_header_t tcp_hdr = Net::load<Net::tcp_header_t>(stream);
      auto bytes = ipv6_hdr.payload_length - tcp_hdr.size();
      packet.data = new char[bytes];
      read_data(stream, bytes, packet.data);
      packet.data_len = bytes;
      packet.src_port = tcp_hdr.src_port;
      packet.dst_port = tcp_hdr.dst_port;
      packet.ack_num = tcp_hdr.ack_num;
      packet.seq_num = tcp_hdr.seq_num;
      packet.hashcode = std::hash<Packet>{}(packet);
      packet.type = pType::TCP;
    } else if (ipv6_hdr.next_header == IP_UDP_PROTOCOL) {
      Net::udp_header_t udp_hdr = Net::load<Net::udp_header_t>(stream);
      // udp data size in bytes
      size_t bytes = (size_t) (udp_hdr.length - 8);
      // currently we read data into string in hex
      packet.data_len = bytes;
      packet.data = new char[bytes];
      read_data(stream, bytes, packet.data);
      packet.src_port = udp_hdr.src_port;
      packet.dst_port = udp_hdr.dst_port;
      packet.hashcode = std::hash<Packet>{}(packet);
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


