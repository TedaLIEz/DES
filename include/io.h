//
// Created by aLIEzTed on 6/4/17.
//

#ifndef DES_IO_H
#define DES_IO_H
#include <iostream>
#include "pcap_encode.h"
#include <unordered_map>
#include "helper.h"
namespace IO {
namespace pcap {
inline void save_pcap(const std::string prefix, PcapEncoder::pcap_hdr_t hdr, const std::unordered_map<size_t, std::vector<PcapEncoder::Packet>> &map) {
  for (auto it : map) {
    if (!it.second.empty()) {
      auto p = it.second[0];
      std::ostringstream oss;
      oss << prefix << "[";
      if (p.src_addr < p.dst_addr) {
        oss << p.src_addr << "][" << p.src_port << "][" << p.dst_addr << "][" << p.dst_port << "]";
      } else {
        oss << p.dst_addr << "][" << p.dst_port << "][" << p.src_addr << "][" << p.src_port << "]";
      }
      oss << ".pcap";
      std::ofstream out(oss.str());
      out.write(static_cast<char *>(static_cast<void *>(&hdr)), sizeof(hdr));
      for (auto e : it.second) {
        out.write(e.ori_data, e.ori_len);
      }
      out.close();
    }
  }
}
}

namespace txt {
inline void save_udp_txt(const std::unordered_map<size_t, std::vector<PcapEncoder::Packet>> &map) {
  for (auto it : map) {
    if (!it.second.empty()) {
      auto p = it.second[0];
      std::ostringstream oss;
      oss << "UDP" << "[";
      if (p.src_addr < p.dst_addr) {
        oss << p.src_addr << "][" << p.src_port << "][" << p.dst_addr << "][" << p.dst_port << "]";
      } else {
        oss << p.dst_addr << "][" << p.dst_port << "][" << p.src_addr << "][" << p.src_port << "]";
      }
      oss << ".txt";
      std::ofstream out(oss.str());
      for (auto e : it.second) {
#ifdef MY_DEBUG
        std::cout << "time " << e.ts << std::endl;
        std::cout << "src " << e.src_addr << ":" << e.src_port << std::endl;
        std::cout << "dst " << e.dst_addr << ":" << e.dst_port << std::endl;
#endif
        out << "src " << e.src_addr << ":" << e.src_port << std::endl;
        out << "dst " << e.dst_addr << ":" << e.dst_port << std::endl;
        out.write(e.data, e.data_len);
        out << "\n\n";
      }
      out.close();
    }
  }
}
}

}

#endif //DES_IO_H
