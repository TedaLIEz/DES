//
// Created by aLIEzTed on 5/10/17.
// Implementation of DAE in mode ECB
//
#include "des.h"
#include "helper.h"
#include "keygen.h"
#include <fstream>
Pi DAE::toIP(uint64_t in) {
  uint64_t t = in;
  for (int i = 0; i < 64; ++i) {
    setBit(t, i, getBit(in, imap[i] - 1) == 0);
  }
  Pi rst;
  rst.left = leftPart(t);
  rst.right = rightPart(t);
  return rst;
}

uint32_t DAE::f(uint32_t in, bitset<48> k) {
  return p(s(e(in) ^ k));
}

bitset<48> DAE::e(uint32_t in) {
  bitset<48> rst;
  for (int i = 0; i < 48; i++) {
    int bit = getBit(in, emap[i] - 1);
    rst.set((size_t) (48 - i - 1), bit == 1);
  }
  return rst;
}

uint32_t DAE::s(bitset<48> in) {
  uint32_t rst = 0;
  for (int i = 0; i < 8; i++) {
    int s = (int) subbitset(in, 48 - (i + 1) * 6, 48 - i * 6).to_ulong();
    int tmp = sbox(i, s);
    rst |= (tmp << (28 - (i) * 4));
  }
  return rst;
}

int DAE::sbox(int i, int s) {
  return smap[i][s];
}

uint32_t DAE::p(uint32_t in) {
  uint32_t rst = in;
  for (int i = 0; i < 32; ++i) {
    setBit(rst, i, getBit(in, pmap[i] - 1) == 0);
  }
  return rst;
}

uint64_t DAE::reverseIP(Pi in) {
  uint64_t t = (((uint64_t) in.left) << 32) | in.right;
  auto tmp = t;
  for (int i = 0; i < 64; ++i) {
    setBit(t, i, getBit(tmp, reverseIPmap[i] - 1) == 0);
  }
  return t;
}

DAE::DAE() {
  smap.insert({0, s1map});
  smap.insert({1, s2map});
  smap.insert({2, s3map});
  smap.insert({3, s4map});
  smap.insert({4, s5map});
  smap.insert({5, s6map});
  smap.insert({6, s7map});
  smap.insert({7, s8map});
}

uint64_t DAE::cipher(uint64_t msg, uint64_t key) {
  Keygen gen;
  auto keys = gen.getK(key);
  auto ip = toIP(msg);
  for (int i = 0; i < 15; i++) {
    ip = layer(ip, keys[i]);
  }

  Pi last;
  // The preoutput block is then R16L16 as the doc described
  last.right = ip.right;
  last.left = fproc(ip.left, ip.right, keys[15]);
  return reverseIP(last);
}

Pi DAE::layer(Pi input, bitset<48> k) {
  Pi rst;
  rst.left = input.right;

  rst.right = fproc(input.left, input.right, k);
  return rst;
}

uint32_t DAE::fproc(uint32_t l, uint32_t r, bitset<48> k) {
  return l ^ f(r, k);
}

uint64_t DAE::decipher(uint64_t encrypt, uint64_t key) {
  Keygen gen;
  auto keys = gen.getK(key);
  auto ip = toIP(encrypt);
  for (int i = 15; i >= 1; i--) {
    ip = layer(ip, keys[i]);
  }
  Pi last;
  last.right = ip.right;
  last.left = fproc(ip.left, ip.right, keys[0]);
  return reverseIP(last);
}




int DAE::encrypt(const std::string filepath, const std::string outpath, const uint64_t key) {
  ifstream in(filepath, ios::binary);
  if (!in) {
    return FILE_NOT_FOUND;
  }
  in.seekg(0, in.end);
  uint64_t length = (uint64_t) in.tellg();
  in.seekg(0, in.beg);
  if (std::ifstream(outpath)) {
    std::remove(outpath.c_str());
  }
  ofstream out(outpath, ios::binary);

  if (!out) {
    return FILE_OPEN_ERROR;
  }

  char* block;
  block = new char[8];

  // put file size at head of the file due to course spec
  for (int i = 0; i < 3; i++) {
    out.write(static_cast<char*>(static_cast<void*>(&length)), 8);
  }

  for (int i = 0; i < (length / 8); i++) {
    in.read(block, 8);
    uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
    uint64_t odata;
    odata = cipher(data, key);

    out.write(static_cast<char*>(static_cast<void*>(&odata)), 8);
  }

  memset(block, 0, 8);
  int remain = (int) (length % 8);
  if (remain) {
    in.read(block, remain);
    uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
    uint64_t odata;
    odata = cipher(data, key);
    out.write(static_cast<char*>(static_cast<void*>(&odata)), 8);
  }

  in.close();
  out.close();

  return 0;

}

int DAE::decrypt(const std::string filepath, const std::string outpath, const uint64_t key) {
  ifstream in(filepath, ios::binary);
  if (!in) {
    return FILE_NOT_FOUND;
  }
  if (std::ifstream(outpath)) {
    std::remove(outpath.c_str());
  }
  ofstream out(outpath, ios::binary);

  if (!out) {
    return FILE_OPEN_ERROR;
  }

  in.seekg(0, in.end);
  uint64_t length = (uint64_t) in.tellg();
  in.seekg(0, in.beg);

  char* block;
  block = new char[8];
  // the first three blocks contain the same real file size
  uint64_t real_len(0);
  in.read(block, 8);
  real_len = *static_cast<uint64_t*>(static_cast<void*>(block));
  for (int i = 0; i < 2; i++) {
    in.read(block, 8);
    auto tmp = *static_cast<uint64_t*>(static_cast<void*>(block));
    if (tmp != real_len) {
      return FILE_OPEN_ERROR;
    }
  }
#ifdef MY_DEBUG
  std::cout << "DAE: encrypted length: " << length << std::endl;
  std::cout << "DAE: real length " << real_len << std::endl;
#endif
  for (int i = 0; i < (length / 8) - 4; i++) {
    in.read(block, 8);
    uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
    uint64_t odata;
    odata = decipher(data, key);

    out.write(static_cast<char*>(static_cast<void*>(&odata)), 8);
  }

  in.read(block, 8);
  uint64_t data = *static_cast<uint64_t*>(static_cast<void*>(block));
  uint64_t odata;
  odata = decipher(data, key);
  auto substr = static_cast<char*>(static_cast<void*>(&odata));
  int remain = (int) (8 - (length - 8 * 3- real_len));
  out.write(substr, remain);

  in.close();
  out.close();

  return 0;


}
