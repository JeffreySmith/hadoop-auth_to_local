#pragma once
#include <optional>
#include <string>
#include <vector>


struct Token {
  enum class Type { placeholder, literal, num_fields };
  Type type;
  std::string text;
  int fields = -1;
};

std::optional<std::vector<Token>> tokenize(const std::string &fmt);
std::optional<std::string> format(const std::string &fmt, const std::vector<std::string> &values);
void basic_token_test();
