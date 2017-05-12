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
  uint64_t b = 0x1234567890abcdef;
  Keygen gen;
  DAE dae(b);
  for (auto i = dae.keys.begin(); i != dae.keys.end(); ++i) {
    std::cout << *i << std::endl;
  }
  return 0;
}

