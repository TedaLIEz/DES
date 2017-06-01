//
// Created by aLIEzTed on 6/1/17.
//

#ifndef DES_PCAP_ENCODE_H
#define DES_PCAP_ENCODE_H
#include <iostream>
#include <iomanip>
#include <string>
class PcapEncoder {
  typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
  } pcap_hdr_t;

  typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
  } pcaprec_hdr_t;

  typedef struct pcaprec_s {
    pcaprec_hdr_t hdr;         /* packet header */
    void *data;                /* packet data */
  } pcaprec_t;
  pcap_hdr_t read_pcap_file_header(std::istream &stream);
  pcaprec_t read_packet(std::istream &stream);
  pcaprec_hdr_t read_pcap_packet_header(std::istream &stream);
  template<typename T>
  void dump(const std::string tag, T t) {
    std::cout << tag << " in hex: "
              << std::hex
              << std::noshowbase
              << std::setw(sizeof(T) * 2)
              << std::setfill('0')
              << t << std::endl;
  }
 public:
  int read(const std::string filename);
};

#endif //DES_PCAP_ENCODE_H
