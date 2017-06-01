#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <helper.h>
#include <fstream>
#include "aes.h"
/*
 * Multiplication in GF(2^8)
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Irreducible polynomial m(x) = x8 + x4 + x3 + x + 1
 */
uint8_t AES::gmult(uint8_t a, uint8_t b) {

  uint8_t p = 0, i = 0, hbs = 0;

  for (i = 0; i < 8; i++) {
    if (b & 1) {
      p ^= a;
    }

    hbs = (uint8_t) (a & 0x80);
    a <<= 1;
    if (hbs) a ^= 0x1b; // 0000 0001 0001 1011
    b >>= 1;
  }

  return (uint8_t) p;
}

/*
 * Addition of 4 byte words
 * m(x) = x4+1
 */
void AES::coef_add(uint8_t a[], uint8_t b[], uint8_t d[]) {

  d[0] = a[0] ^ b[0];
  d[1] = a[1] ^ b[1];
  d[2] = a[2] ^ b[2];
  d[3] = a[3] ^ b[3];
}

/*
 * Multiplication of 4 byte words
 * m(x) = x4+1
 */
void AES::coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) {

  d[0] = gmult(a[0], b[0]) ^ gmult(a[3], b[1]) ^ gmult(a[2], b[2]) ^ gmult(a[1], b[3]);
  d[1] = gmult(a[1], b[0]) ^ gmult(a[0], b[1]) ^ gmult(a[3], b[2]) ^ gmult(a[2], b[3]);
  d[2] = gmult(a[2], b[0]) ^ gmult(a[1], b[1]) ^ gmult(a[0], b[2]) ^ gmult(a[3], b[3]);
  d[3] = gmult(a[3], b[0]) ^ gmult(a[2], b[1]) ^ gmult(a[1], b[2]) ^ gmult(a[0], b[3]);
}

uint8_t *AES::Rcon(uint8_t i) {

  if (i == 1) {
    R[0] = 0x01; // x^(1-1) = x^0 = 1
  } else if (i > 1) {
    R[0] = 0x02;
    i--;
    while (i - 1 > 0) {
      R[0] = gmult(R[0], 0x02);
      i--;
    }
  }

  return R;
}

/*
 * Transformation in the Cipher and Inverse Cipher in which a Round 
 * Key is added to the State using an XOR operation. The length of a 
 * Round Key equals the size of the State (i.e., for Nb = 4, the Round 
 * Key length equals 128 bits/16 bytes).
 */
void AES::add_round_key(uint8_t *state, uint8_t *w, uint8_t r) {

  uint8_t c;

  for (c = 0; c < Nb; c++) {
    state[Nb * 0 + c] = state[Nb * 0 + c] ^ w[4 * Nb * r + 4 * c + 0];   //debug, so it works for Nb !=4
    state[Nb * 1 + c] = state[Nb * 1 + c] ^ w[4 * Nb * r + 4 * c + 1];
    state[Nb * 2 + c] = state[Nb * 2 + c] ^ w[4 * Nb * r + 4 * c + 2];
    state[Nb * 3 + c] = state[Nb * 3 + c] ^ w[4 * Nb * r + 4 * c + 3];
  }
}

/*
 * Transformation in the Cipher that takes all of the columns of the 
 * State and mixes their data (independently of one another) to 
 * produce new columns.
 */
void AES::mix_columns(uint8_t *state) {

  uint8_t a[] = {0x02, 0x01, 0x01, 0x03}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
  uint8_t i, j, col[4], res[4];

  for (j = 0; j < Nb; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[Nb * i + j];
    }

    coef_mult(a, col, res);

    for (i = 0; i < 4; i++) {
      state[Nb * i + j] = res[i];
    }
  }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * MixColumns().
 */
void AES::inv_mix_columns(uint8_t *state) {

  uint8_t a[] = {0x0e, 0x09, 0x0d, 0x0b}; // a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
  uint8_t i, j, col[4], res[4];

  for (j = 0; j < Nb; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[Nb * i + j];
    }

    coef_mult(a, col, res);

    for (i = 0; i < 4; i++) {
      state[Nb * i + j] = res[i];
    }
  }
}

/*
 * Transformation in the Cipher that processes the State by cyclically 
 * shifting the last three rows of the State by different offsets. 
 */
void AES::shift_rows(uint8_t *state) {

  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    // shift(1,4)=1; shift(2,4)=2; shift(3,4)=3
    // shift(r, 4) = r;
    s = 0;
    while (s < i) {
      tmp = state[Nb * i + 0];

      for (k = 1; k < Nb; k++) {
        state[Nb * i + k - 1] = state[Nb * i + k];
      }

      state[Nb * i + Nb - 1] = tmp;
      s++;
    }
  }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * ShiftRows().
 */
void AES::inv_shift_rows(uint8_t *state) {

  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    s = 0;
    while (s < i) {
      tmp = state[Nb * i + Nb - 1];

      for (k = (uint8_t) (Nb - 1); k > 0; k--) {
        state[Nb * i + k] = state[Nb * i + k - 1];
      }

      state[Nb * i + 0] = tmp;
      s++;
    }
  }
}

/*
 * Transformation in the Cipher that processes the State using a non­
 * linear byte substitution table (S-box) that operates on each of the 
 * State bytes independently. 
 */
void AES::sub_bytes(uint8_t *state) {

  uint8_t i, j;
  uint8_t row, col;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      row = (uint8_t) ((state[Nb * i + j] & 0xf0) >> 4);
      col = (uint8_t) (state[Nb * i + j] & 0x0f);
      state[Nb * i + j] = s_box[16 * row + col];
    }
  }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * SubBytes().
 */
void AES::inv_sub_bytes(uint8_t *state) {

  uint8_t i, j;
  uint8_t row, col;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      row = (uint8_t) ((state[Nb * i + j] & 0xf0) >> 4);
      col = (uint8_t) (state[Nb * i + j] & 0x0f);
      state[Nb * i + j] = inv_s_box[16 * row + col];
    }
  }
}

/*
 * Function used in the Key Expansion routine that takes a four-byte 
 * input word and applies an S-box to each of the four bytes to 
 * produce an output word.
 */
void AES::sub_word(uint8_t *w) {

  uint8_t i;

  for (i = 0; i < 4; i++) {
    w[i] = s_box[16 * ((w[i] & 0xf0) >> 4) + (w[i] & 0x0f)];
  }
}

/*
 * Function used in the Key Expansion routine that takes a four-byte 
 * word and performs a cyclic permutation. 
 */
void AES::rot_word(uint8_t *w) {

  uint8_t tmp;
  uint8_t i;

  tmp = w[0];

  for (i = 0; i < 3; i++) {
    w[i] = w[i + 1];
  }

  w[3] = tmp;
}

/*
 * Key Expansion
 */
void AES::key_expansion(uint8_t *key, uint8_t *w) {

  uint8_t tmp[4];
  uint8_t i;
  uint8_t len = (uint8_t) (Nb * (Nr + 1));

  for (i = 0; i < Nk; i++) {
    w[4 * i + 0] = key[4 * i + 0];
    w[4 * i + 1] = key[4 * i + 1];
    w[4 * i + 2] = key[4 * i + 2];
    w[4 * i + 3] = key[4 * i + 3];
  }

  for (i = (uint8_t) Nk; i < len; i++) {
    tmp[0] = w[4 * (i - 1) + 0];
    tmp[1] = w[4 * (i - 1) + 1];
    tmp[2] = w[4 * (i - 1) + 2];
    tmp[3] = w[4 * (i - 1) + 3];

    if (i % Nk == 0) {

      rot_word(tmp);
      sub_word(tmp);
      coef_add(tmp, Rcon((uint8_t) (i / Nk)), tmp);

    } else if (Nk > 6 && i % Nk == 4) {

      sub_word(tmp);

    }

    w[4 * i + 0] = w[4 * (i - Nk) + 0] ^ tmp[0];
    w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ tmp[1];
    w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ tmp[2];
    w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ tmp[3];
  }
}

void AES::cipher(uint8_t *in, uint8_t *out) {
  uint8_t* state = new uint8_t[4 * Nb];
//  uint8_t state[4 * Nb];
  uint8_t r, i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[Nb * i + j] = in[i + 4 * j];
    }
  }

  add_round_key(state, w, 0);

  for (r = 1; r < Nr; r++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, w, r);
  }

  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, w, Nr);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[Nb * i + j];
    }
  }
}

void AES::decipher(uint8_t *in, uint8_t *out) {

  uint8_t* state = new uint8_t[4 * Nb];
//  uint8_t state[4 * Nb];
  uint8_t r, i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[Nb * i + j] = in[i + 4 * j];
    }
  }

  add_round_key(state, w, Nr);

  for (r = (uint8_t) (Nr - 1); r >= 1; r--) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, w, r);
    inv_mix_columns(state);
  }

  inv_shift_rows(state);
  inv_sub_bytes(state);
  add_round_key(state, w, 0);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[Nb * i + j];
    }
  }
}

AES::AES(uint8_t key[], int keylen) {
  switch (keylen) {
    default:
    case 16:
      Nk = 4;
      Nr = 10;
      break;
    case 24:
      Nk = 6;
      Nr = 12;
      break;
    case 32:
      Nk = 8;
      Nr = 14;
      break;
  }
  w = (uint8_t *) malloc((size_t) (Nb * (Nr + 1) * 4));
  key_expansion(key, w);
}

int AES::encrypt(const std::string inpath, const std::string outpath) {
  std::ifstream in(inpath, std::ios::binary);
  if (!in) {
    return FILE_NOT_FOUND;
  }
  in.seekg(0, in.end);
  uint64_t length = (uint64_t) in.tellg();
  in.seekg(0, in.beg);
  if (std::ifstream(outpath)) {
    std::remove(outpath.c_str());
  }
  std::ofstream out(outpath, std::ios::binary);


  if (!out) {
    return FILE_OPEN_ERROR;
  }

  char* block;
  block = new char[16];

  // write length at the head of file trice due to class spec
  for (int i = 0; i < 3; i++) {
    out.write(static_cast<char*>(static_cast<void*>(&length)), 16);
  }
  for (int i = 0; i < (length * 8 / 128); i++) {
    in.read(block, 16);
    uint8_t* data = static_cast<uint8_t*>(static_cast<void*>(block));
    uint8_t odata[16] = {0};
    cipher(data, odata);

    out.write(static_cast<char*>(static_cast<void*>(odata)), 16);
  }

  memset(block, 0, 16);
  int remain = (int) (length * 8 % 128);
  if (remain) {
    // read by byte
    in.read(block, remain / 8);
    uint8_t* data = static_cast<uint8_t*>(static_cast<void*>(block));
    uint8_t odata[16] = {0};
    cipher(data, odata);
    out.write(static_cast<char*>(static_cast<void*>(&odata)), 16);
  }


  in.close();
  out.close();

  return 0;
}

int AES::decrypt(const std::string inpath, const std::string outpath) {

  std::ifstream in(inpath, std::ios::binary);
  if (!in) {
    return FILE_NOT_FOUND;
  }
  if (std::ifstream(outpath)) {
    std::remove(outpath.c_str());
  }
  std::ofstream out(outpath, std::ios::binary);

  if (!out) {
    return FILE_OPEN_ERROR;
  }

  in.seekg(0, in.end);
  uint64_t length = (uint64_t) in.tellg();
  in.seekg(0, in.beg);


  char* block;
  block = new char[16];
  in.read(block, 16);
  uint64_t real_len = *static_cast<uint64_t*>(static_cast<void*>(block));
  for (int i = 0; i < 2; i++) {
    in.read(block, 16);
    auto tmp = *static_cast<uint64_t*>(static_cast<void*>(block));
    if (tmp != real_len) {
      return FILE_OPEN_ERROR;
    }
  }

  std::cout << "AES: file length" << length << std::endl;
  std::cout << "AES: real length " << real_len << std::endl;
  for (int i = 0; i < (length * 8 / 128) - 4; i++) {
    in.read(block, 16);

    uint8_t* data = static_cast<uint8_t*>(static_cast<void*>(block));
    uint8_t odata[16] = {0};
    decipher(data, odata);

    out.write(static_cast<char*>(static_cast<void*>(odata)), 16);
  }

  in.read(block, 16);
  uint8_t* data = static_cast<uint8_t*>(static_cast<void*>(block));
  uint8_t odata[16] = {0};
  decipher(data, odata);

  int remain = (int) (16 - (length - 16 * 3- real_len));
  out.write(static_cast<char*>(static_cast<void*>(&odata)), remain);

  in.close();
  out.close();

  return 0;
}