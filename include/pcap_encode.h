//
// Created by aLIEzTed on 6/1/17.
//

#ifndef DES_PCAP_ENCODE_H
#define DES_PCAP_ENCODE_H
#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <vector>
#include "helper.h"
class PcapEncoder {
 private:
  /**
   * Packet used in code
   */
  enum class pType : char { TCP = 1, UDP = 2, OTHERS = 3 };
  using port_t = uint16_t;

  typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
    void dump() {
#ifdef MY_DEBUG
      std::cout << std::endl << "===== PCAP packet header ===== " << std::endl;
      ::dump("ts_sec", ts_sec);
      ::dump("ts_usec", ts_usec);
      std::cout << "incl_len: " << incl_len << std::endl;
      std::cout << "orig_len: " << orig_len << std::endl;
      std::cout << "===== end of PCAP packet header ===== " << std::endl << std::endl;
#endif
    }
  } pcaprec_hdr_t;

 public:

  typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
    void dump() {
      std::cout << std::endl << "===== PCAP file header ===== " << std::endl;
      ::dump("magic_number", magic_number);
      ::dump("version major", version_major);
      ::dump("version minor", version_minor);
      ::dump("thiszone", thiszone);
      ::dump("sigfigs", sigfigs);
      ::dump("snaplen", snaplen);
      ::dump("network", network);
      std::cout << "===== end of PCAP file header =====" << std::endl << std::endl;
    }
  } pcap_hdr_t;
  // packet structure used for future indexing
  typedef struct _Packet {
    // TODO: add mac addr to this struct
    uint32_t ts;               /* unix timestamp for this packet */
    pType type = pType::OTHERS;              /* 1 for tcp, 2 for udp, 0 for others */
    port_t src_port;
    port_t dst_port;
    std::string src_addr;
    std::string dst_addr;
    uint32_t seq_num = 0; /* sequence number used in tcp packet */
    uint32_t ack_num = 0; /* acknowledgment number used in tcp packet */
    char* data;     /* packet data */
    size_t data_len; /* length of packet data */
    size_t hashcode = 0;      /* hashcode of this packet */
    char* ori_data;       /* whole data of this pcap packet, including pcap_packet_header */
    size_t ori_len;       /* whole len of pcap packet */
    void dump() {
      std::cout << std::endl << "===== Packet =====" << std::endl;
      std::cout << "ts: " << ts << std::endl;
      std::cout << "src_addr: " << src_addr << std::endl;
      std::cout << "dst_addr: " << dst_addr << std::endl;
      std::cout << "src_port: " << src_port << std::endl;
      std::cout << "dst_port: " << dst_port << std::endl;
      std::string t;
      switch (type) {
        case pType::TCP :
          t = "TCP";
          break;
        case pType::UDP:
          t = "UDP";
          break;
        default:
          t = "Others";
          break;
      }
      std::cout << "transmission layer protocol: " << t << std::endl;
      auto s = convert_data(data, data_len);
      s = s.length() == 0 ? "no data" : s;
      std::cout << "data: " <<  s << std::endl;
      std::cout << "origin: data: " << convert_data(ori_data, ori_len) << std::endl;
      std::cout << "hashcode: " << hashcode << std::endl;
      std::cout << "===== End of packet =====" << std::endl << std::endl;
    }
    bool operator==(const _Packet& other) {
      return type == other.type && src_port == other.src_port
          && dst_port == other.dst_port && src_addr == other.src_addr
          && dst_addr == other.dst_addr;

    }
  } Packet;
  /**
   * Read a pcap format file
   * @param filename filepath of the pcap file
   * @return <tt>0</tt> if read success, other val if falied
   */
  int analyze_pcap(const std::string filename);


 private:




  pcap_hdr_t pcap_hdr;
  std::unordered_map<size_t, std::vector<Packet>> udp_map;
  std::unordered_map<size_t, std::vector<Packet>> tcp_map;

  void reassemble_udp_packet(Packet &packet);

  void reassemble_tcp_packet(Packet &packet);

  int save_to_pcap();
  int save_tcp_txt(const std::string filename);
  int save_udp_txt(const std::string filename);
  /**
   * read the file header of pcap file
   * @param stream input file stream
   * @return @see pcap_hdr_t
   */
  pcap_hdr_t read_pcap_file_header(std::istream &stream);
  /**
   * read packet from file
   * @param stream input file stream
   * @return @see pcaprec_t
   */
  Packet read_packet(std::istream &stream);
  /**
   * read pcap header of each packet in file
   * @param stream input file stream
   * @return @see pcaprec_hdr_t
   */
  pcaprec_hdr_t read_pcap_packet_header(std::istream &stream);

  void read_data(std::istream &stream, size_t size, char* buffer);

  void filter(Packet &packet);
  friend bool operator< (const Packet &i, const Packet &j) {
    return i.ts < j.ts;
  }

};



#endif //DES_PCAP_ENCODE_H
