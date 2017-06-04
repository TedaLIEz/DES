//
// Created by aLIEzTed on 6/4/17.
//

#ifndef DES_IO_H
#define DES_IO_H
#include <iostream>
#include "pcap_encode.h"
#include <unordered_map>
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
inline void save_txt(const std::string prefix, const std::unordered_map<size_t, std::vector<PcapEncoder::Packet>> &map) {

}
}

}

#endif //DES_IO_H
