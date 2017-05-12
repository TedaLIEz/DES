#include <iostream>
#include <gtk/gtk.h>
#include "dae.h"
#include "keygen.h"
#include "helper.h"
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
//  GtkWidget *window;
//
//  gtk_init(&argc, &argv);
//
//  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
//  gtk_widget_show(window);
//
//  gtk_main();
  uint64_t key = 0b0110001101101111011011010111000001110101011101000110010101110010;
  key = 0x0123456789ABCDEF;
  DAE dae(key);
  uint64_t msg(0b0110110001100101011000010111001001101110011010010110111001100111);
  msg = 0x0000000000000000;
  auto rst = dae.cipher(msg);
  std::cout << "Debug: " << std::endl;
  std::cout << "Msg: " << printHex(msg) << std::endl;
  std::cout << "Key: " << printHex(key) << std::endl;
  std::cout << "Rst: " << printHex(rst) << std::endl;
  return 0;
}

