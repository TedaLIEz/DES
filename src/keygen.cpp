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

