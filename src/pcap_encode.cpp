//
// Created by aLIEzTed on 6/1/17.
//

#include "pcap_encode.h"
#include <fstream>
#include <helper.h>
int PcapEncoder::read(const std::string filename) {
  std::ifstream in(filename, std::ios::binary);
  if (!in) {
    return FILE_NOT_FOUND;
  }
  auto pcap_file_header = read_pcap_file_header(in);

  dump("magic_number", pcap_file_header.magic_number);
  dump("version major", pcap_file_header.version_major);
  dump("version minor", pcap_file_header.version_minor);
  dump("thiszone", pcap_file_header.thiszone);
  dump("sigfigs", pcap_file_header.sigfigs);
  dump("snaplen", pcap_file_header.snaplen);
  dump("network", pcap_file_header.network);
  // TODO: read packet one by one and do filter
  auto pcap_packet_header = read_pcap_packet_header(in);
//  dump("packet orilen", pcap_packet_header.orig_len);
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


PcapEncoder::pcaprec_t PcapEncoder::read_packet(std::istream &stream) {

}