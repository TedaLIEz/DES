//
// Created by aLIEzTed on 5/11/17.
//

#include "keygen.h"
#include "helper.h"

Key Keygen::pc1(uint64_t k) {
  Key key;
  for (int i = 0; i < 28; i++) {
    int bit = getBit(k, pc1map[i] - 1);
    key.c.set((size_t) (28 - i - 1), bit);
  }
  for (int i = 0; i < 28; i++) {
    int bit = getBit(k, pc1map[i + 28] - 1);
    key.d.set((size_t) (28 - i - 1), bit);
  }
  return key;
}

Key Keygen::leftShift(Key key, int index) {

}

bitset<48> Keygen::pc2(Key key) {
  bitset<48> rst(0);
  bitset<56> k(key.c.to_ullong());
  k = k << 28;
  k |= bitset<56>(key.d.to_ulong());
  for (int i = 0; i < 48; i++) {
    int bit = k[56 - pc2map[i]];
    rst.set((size_t) (48 - i - 1), bit);
  }
  return rst;
}

