//
// Created by aLIEzTed on 5/11/17.
//

#ifndef DES_KEYGEN_H
#define DES_KEYGEN_H
#include <bitset>
#include <vector>
using namespace std;
struct Key {
  Key() : c(), d() {}
  bitset<28> c;
  bitset<28> d;
};

class Keygen {
 private:
  int pc1map[56] = {
      57, 49, 41, 33, 25, 17, 9,
      1, 58, 50, 42, 34, 26, 18,
      10, 2, 59, 51, 43, 35, 27,
      19, 11, 3, 60, 52, 44, 36,

      63, 55, 47, 39, 31, 23, 15,
      7, 62, 54, 46, 38, 30, 22,
      14, 6, 61, 53, 45, 37, 29,
      21, 13, 5, 28, 20, 12, 4
  };
 public:
  Key pc1(uint64_t key);
  vector<Key> getK(uint64_t key);
};

#endif //DES_KEYGEN_H
