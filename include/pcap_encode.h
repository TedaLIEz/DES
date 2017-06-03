//
// Created by aLIEzTed on 6/1/17.
//

#ifndef DES_PCAP_ENCODE_H
#define DES_PCAP_ENCODE_H
#include <iostream>
#include <iomanip>
#include <string>
#include "helper.h"
class PcapEncoder {
  using port_t = uint16_t;
  typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
    void dump() {
#ifdef MY_DEBUG
      std::cout << std::endl << "===== PCAP file header ===== " << std::endl;
      ::dump("magic_number", magic_number);
      ::dump("version major", version_major);
      ::dump("version minor", version_minor);
      ::dump("thiszone", thiszone);
      ::dump("sigfigs", sigfigs);
      ::dump("snaplen", snaplen);
      ::dump("network", network);
      std::cout << "===== end of PCAP file header =====" << std::endl << std::endl;
#endif
    }
  } pcap_hdr_t;

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

  /**
   * Packet used in code
   */
  enum class pType : char { TCP = 1, UDP = 2, OTHERS = 3 };
  typedef struct _Packet {
    // TODO: hashcode for this struct
    pcaprec_hdr_t hdr;         /* packet header */
    pType type;              /* 1 for tcp, 2 for udp, 0 for others */
    port_t src_port;
    port_t dst_port;
    std::string src_addr;
    std::string dst_addr;
    std::string data;                /* packet data */
    void dump() {
      std::cout << std::endl << "===== Packet =====" << std::endl;
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
      std::cout << "data: " << data << std::endl;
      std::cout << "===== End of packet =====" << std::endl << std::endl;
    }
  } Packet;
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
  std::string convert_data(char *buffer, int size) const;

  std::string read_data(std::istream &stream, int size);
 public:
  /**
   * Read a pcap format file
   * @param filename filepath of the pcap file
   * @return <tt>0</tt> if read success, other val if falied
   */
  int read(const std::string filename);
};

#endif //DES_PCAP_ENCODE_H
