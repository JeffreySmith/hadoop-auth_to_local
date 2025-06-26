#pragma once
#include <iostream>
#define DEBUG(msg) \
  do { if (debug_mode) {std::cerr << msg << "\n";}} while (0)
extern bool debug_mode;
