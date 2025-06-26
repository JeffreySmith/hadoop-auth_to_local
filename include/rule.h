#pragma once

#include <regex>
#include <vector>
#include <token.h>
#include <tuple>
#include <optional>

struct SedRule {
    std::string pattern;
    std::string replacement;
    std::string flags;
};


struct Rule {
  int num_fields;
  std::string fmt;
  std::vector<Token> tokens;
  std::string token_string;
  std::string rule;
  std::vector<std::string> regex_flags;
  std::regex match_regex;
  std::string regex_match_string;
  std::optional<SedRule> sed_rule;
  std::tuple<std::string,std::string> sed_replace = {"", ""};
};



std::optional<Rule> parse_rule(const std::string &auth_rule);
int number_of_fields(const std::string &principal);
std::vector<std::string> split(const std::string &s, const std::string &delimiter);
int fieldMatch(const Rule &rule, const std::string &principal, std::string &formattedString);
bool shortRuleMatches(const Rule &rule, const std::string &modified_principal);
int replaceMatchingOutput(const Rule &rule, std::string &modified_principal, std::string &output);
bool matchPrincipalAgainstRules(const std::vector<Rule> rules, const std::string &principal, std::string &output);
int transformPrincipal(const Rule &rule, const std::string &principal, std::string &output);
std::optional<SedRule> parse_sed_rule(const std::string &input_rule);
std::string trim(const std::string &s);
