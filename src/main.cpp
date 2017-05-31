#include <iostream>
#include "des.h"
#include "keygen.h"
#include "helper.h"
#include <chrono>
#include "aes.h"

int main(int argc,
         char *argv[]) {

//  uint64_t key = 0b0110001101101111011011010111000001110101011101000110010101110010;
//  key = 0x0123456789ABCDEF;
//
//  DAE dae;
//  dae.encrypt("test.txt", "encrypt.txt", key);
//  dae.decrypt("encrypt.txt", "decipher.txt", key);
//  uint64_t msg(0b0110110001100101011000010111001001101110011010010110111001100111);
//  msg = 0x0123456789ABCDEF;
//  auto start = std::chrono::high_resolution_clock::now();
//  auto rst = dae.cipher(msg, key);
//  auto finish = std::chrono::high_resolution_clock::now();
//  std::cout << "Msg " << printHex(msg) << std::endl;
//  std::cout << "Key " << printHex(key) << std::endl;
//  std::cout << "Rst " << printHex(rst) << std::endl;
//  std::cout << "=============Debug=============" << std::endl;
//  std::chrono::duration<double> elapsed = finish - start;
//  std::cout << "Encipher runtime " << elapsed.count() << "s" << std::endl;
//  std::cout << "=============Debug=============" << std::endl;
//  start = std::chrono::high_resolution_clock::now();
//  auto result = dae.decipher(rst, key);
//  finish = std::chrono::high_resolution_clock::now();
//  elapsed = finish - start;
//  std::cout << "Decipher " << printHex(result) << std::endl;
//  std::cout << "Decipher runtime " << elapsed.count() << "s" << std::endl;


  /* 256 bit key */
  uint8_t key[] = {
      0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f};
////
  uint8_t in[] = {
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb,
      0xcc, 0xdd, 0xee, 0xff};
//
  uint8_t out[16]; // 128
//
//
  AES aes(key, sizeof(key));
//  auto rst = aes.encrypt("test.txt", "encrypt.txt");
//  std::cout << rst << std::endl;
//  aes.decrypt("encrypt.txt", "decipher.txt");
//
  aes.cipher(in, out);
//
  printf("in:\n");
  for (int i = 0; i < 4; i++) {
    printf("%x %x %x %x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
  }
  printf("\n");
  printf("out:\n");
//
  for (int i = 0; i < 4; i++) {
    printf("%x %x %x %x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
  }
//
  printf("\n");
//
  aes.decipher(out, in);

  printf("decipher msg:\n");
  for (int i = 0; i < 4; i++) {
    printf("%x %x %x %x ", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
  }

  printf("\n");
  printf("key:\n");
  for (int i = 0; i < 4; i++) {
    printf("%x %x %x %x ", key[4 * i + 0], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
  }
  return 0;
}




