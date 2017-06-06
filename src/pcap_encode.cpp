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
    filter(p);
  }

  save_to_pcap();
  auto found = filename.find_last_of(".");
  auto substr = filename.substr(0, found);
  auto rst = save_tcp_txt(substr);
  if (!rst) {
    return FILE_CREATE_ERROR;
  }
  rst = save_udp_txt(substr);
  if (!rst) {
    return FILE_CREATE_ERROR;
  }
  // we have a end of line here
  assert(in.eof());
  in.close();
  return 0;
}


void PcapEncoder::filter(Packet &packet) {
  if (packet.type == pType::UDP) {
    reassemble_udp_packet(packet);
  } else if (packet.type == pType::TCP) {
    reassemble_tcp_packet(packet);
  }
}

int PcapEncoder::save_to_pcap() {
  int rst1 = IO::save_pcap("UDP", pcap_hdr, udp_map);
  int rst2 = IO::save_pcap("TCP", pcap_hdr, tcp_map);
  if (!rst1 && !rst2) {
    return 0;
  } else {
    return FILE_OPEN_ERROR;
  }
}

int PcapEncoder::save_udp_txt(const std::string filename) {
  auto outpath = filename + "_udp.txt";
  if (std::ifstream(outpath)) {
    std::remove(outpath.c_str());
  }
  std::ofstream stream(outpath);
  if (!stream) {
    return FILE_CREATE_ERROR;
  }
  for (auto it : udp_map) {
    if (!it.second.empty()) {
      for (auto e : it.second) {
#ifdef MY_DEBUG
        std::cout << "time " << e.ts << std::endl;
        std::cout << "src " << e.src_addr << ":" << e.src_port << std::endl;
        std::cout << "dst " << e.dst_addr << ":" << e.dst_port << std::endl;
#endif
        stream << "time " << e.ts << std::endl;
        stream << "src " << e.src_addr << ":" << e.src_port << std::endl;
        stream << "dst " << e.dst_addr << ":" << e.dst_port << std::endl;
        stream.write(e.data, e.data_len);
        stream << "\n\n";
      }
    }
  }
  stream.close();
  return 0;
}

int PcapEncoder::save_tcp_txt(const std::string filename) {
  auto outpath = filename + "_tcp.txt";
  if (std::ifstream(outpath)) {
    std::remove(outpath.c_str());
  }
  std::ofstream stream(outpath);
  if (!stream) {
    return FILE_CREATE_ERROR;
  }
  for (auto it : tcp_map) {
    if (!it.second.empty() && (it.second[0].src_port == 80 || it.second[0].dst_port == 80)) {
      auto p = it.second[0];
      for (auto v : it.second) {
        stream << "time " << v.ts << std::endl;
        stream << "src " << v.src_addr << ":" << v.src_port << std::endl;
        stream << "dst " << v.dst_addr << ":" << v.dst_port << std::endl;
        if (v.data_len != 0) {
          stream.write(v.data, v.data_len);
        }
        stream << std::endl;
      }
    }
  }
  stream.close();
  return 0;
}

void PcapEncoder::reassemble_tcp_packet(Packet &packet) {
  if (tcp_map.find(packet.hashcode) == tcp_map.end()) {
    tcp_map[packet.hashcode] = std::vector<Packet>();
  }
  std::vector<Packet> *v = &tcp_map[packet.hashcode];
  if (v->empty()) {
    v->push_back(packet);
  }
  if (v->back().dst_addr.compare(packet.dst_addr) == 0) {
    // The packet behind the last packet in vector
    if (v->back().seq_num + v->back().data_len <= packet.seq_num) {
      v->push_back(packet);
    }
      // Find the position where the packet should be
    else {
      for (int i = v->size() - 2; i >= 0; i--) {
        if ((*v)[i].dst_addr.compare(packet.dst_addr) == 0
            && (*v)[i].seq_num + (*v)[i].data_len <= packet.seq_num) {
          v->insert(v->begin() + i + 1, packet);
          break;
        }
        // If have not match, throw the packet
      }
    }
  }
  else {
    if (v->back().ack_num == packet.seq_num) {
      v->push_back(packet);
    }
    // Else throw the packet
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

void PcapEncoder::read_data(std::istream &stream, size_t size, char *buffer) {
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


