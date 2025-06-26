#include <cctype>
#include <cstddef>
#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include <assert.h>
#include <token.h>
#include <debug.h>

std::optional<std::vector<Token>> tokenize(const std::string &fmt) {
  std::vector<Token> tokens;
  tokens.reserve(fmt.length());
  if (fmt.empty()) {
    return std::nullopt;
  }

  if (fmt == "DEFAULT"){
    return std::nullopt;
  }
  std::size_t i = 0, end = fmt.length() ;
  while (i < end) {
    if (fmt[i] == '\\' && (i + 1) < end && fmt[i + 1] == '$') {
      
      i += 2;
      tokens.push_back(Token{.type = Token::Type::literal, .text = "$"});
    } else if (fmt[i] == '$' && (i + 1) < end && std::isdigit(fmt[i + 1])) {
      size_t start = i;
      i += 2;
      while (i < end && std::isdigit(fmt[i])) {
        i++;
      }
      tokens.push_back(Token{.type = Token::Type::placeholder,
                             .text = fmt.substr(start, i - start)});
    } else {
      size_t start = i;
      while (i < end &&
             !(fmt[i] == '$' && (i + 1 < end) && std::isdigit(fmt[i + 1])) &&
             !(fmt[i] == '\\' && (i + 1 < end) && fmt[i + 1] == '$')) {
        i++;
      }
      tokens.push_back(Token{.type = Token::Type::literal,
                             .text = fmt.substr(start, i - start)});
    }
  }
  return tokens;
}
std::optional<std::string> format(const std::string &fmt, const std::vector<std::string> &values) {
  std::string result;
  std::vector<Token> tokens = tokenize(fmt).value_or(std::vector<Token>{});
  for (const auto &token : tokens) {
    if (token.type == Token::Type::num_fields) {
      if (token.fields < 0) {
        std::cerr << "Error: no fields detected\n";
        return std::nullopt;
      } else {
      }
    }
    if (token.type == Token::Type::placeholder) {
      size_t idx = 0, pos = 1;
      while (pos < token.text.length() && std::isdigit(token.text[pos])) {
        idx = idx * 10 + (token.text[pos] - '0');
        pos++;
      }
      if (idx < values.size()) {
        result += values[idx];
      } else {
        std::cerr << "Placeholder index out of range\n";
        return std::nullopt;
      }
    } else if (token.type == Token::Type::literal) {
      result.append(token.text);
    }
  }
  return result;
}

void basic_token_test (){
  auto tokens = tokenize("$1$2$10@myhost$0");
  assert(tokens.has_value());
  auto default_rule = tokenize("DEFAULT");
  assert(!default_rule.has_value());

  std::string singleTest = "$1-spark@$0";

  assert(tokenize(singleTest).has_value());
  auto output =
      format(singleTest, std::vector<std::string>{"ADSRE.COM", "kudu"});
  assert(output.has_value());
  assert(output.value() == "kudu-spark@ADSRE.COM");
}
