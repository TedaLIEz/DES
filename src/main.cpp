#include <iostream>
#include <gtk/gtk.h>
#include "dae.h"
#include "keygen.h"
#include "helper.h"
#include <chrono>
#include "aes.h"
//void convert(int s[]) {
//  bitset<6> mask(0b011110);
//  for (uint64_t i = 0; i < 64; i++) {
//    bitset<6> t(i);
//    int a = (t[5] << 1) + t[0];
//    int b = (int) ((t & mask) >> 1).to_ullong();
//    std::cout << s[a * 16 + b] << ",";
//  }
//  std::cout << std::endl;
//  std::cout << std::endl;
//}

int main(int argc,
         char *argv[]) {
////  GtkWidget *window;
////
////  gtk_init(&argc, &argv);
////
////  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
////  gtk_widget_show(window);
////
////  gtk_main();
//  uint64_t key = 0b0110001101101111011011010111000001110101011101000110010101110010;
//  key = 0x0123456789ABCDEF;
//  DAE dae;
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
      0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13,
      0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b,
      0x1c, 0x1d, 0x1e, 0x1f};

  uint8_t in[] = {
      0x00, 0x11, 0x22, 0x33,
      0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb,
      0xcc, 0xdd, 0xee, 0xff};

  uint8_t out[16]; // 128


  AES aes(key, sizeof(key));

  aes.cipher(in, out);

  printf("out:\n");

  for (int i = 0; i < 4; i++) {
    printf("%x %x %x %x ", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
  }

  printf("\n");

  aes.decipher(out, in);

  printf("msg:\n");
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

