#include <algorithm>
#include <iostream>
#include <regex>
#include <optional>
#include <assert.h>
#include <string>
#include <tuple>
#include <token.h>
#include <vector>
#include <rule.h>
#include <debug.h>
#include <coresite.h>

std::string escape_regex_literal(const std::string& literal) {
    static const std::regex re(R"([.^$|()\\[\]{}*+?])");
    return std::regex_replace(literal, re, R"(\$&)");
}

std::string process_java_regex_literals(const std::string& input) {
    std::string output;
    size_t i = 0;
    while (i < input.size()) {
        if (input.substr(i, 2) == "\\Q") {
            i += 2;
            size_t end = input.find("\\E", i);
            if (end == std::string::npos) {
                // Unterminated \Q, treat the rest as literal
                output += escape_regex_literal(input.substr(i));
                break;
            } else {
                output += escape_regex_literal(input.substr(i, end - i));
                i = end + 2;
            }
        } else {
            output += input[i++];
        }
    }
    return output;
}

std::optional<SedRule> parse_sed_rule(const std::string& sed_rule) {
    if (sed_rule.empty()) {
      return std::nullopt;
    }
    if (sed_rule.size() < 3 || sed_rule[0] != 's') {
      std::cerr << "Rule must start with 's' and a delimiter\n";
      std::cerr << "It is: '" << sed_rule << "'\n";
      return std::nullopt;
    }
    char delimiter = sed_rule[1];
    std::string rule = sed_rule.substr(2); //skip the s + delimiter
    size_t pos = 0; 
    std::string part[2];
    int part_idx = 0;
    bool escape = false;
    
    if (std::isalnum(delimiter) || delimiter == '\\' || delimiter == ' ') {
      std::cerr << "Invalid delimiter: '" << delimiter << "'\n";
      return std::nullopt;
    }

    while (pos < rule.size() && part_idx < 2) {
        char c = rule[pos];
        if (escape) {
            part[part_idx] += c;
            escape = false;
        } else if (c == '\\') {
            escape = true;
        } else if (c == delimiter) {
            ++part_idx;
        } else {
            part[part_idx] += c;
        }
        ++pos;
    }

    if (part_idx < 2) {
      std::cerr << "Malformed sed rule: missing delimiters\n";
      return std::nullopt;
    }

    std::string flags;
    if (pos <= rule.size()) {
        flags = rule.substr(pos);
    }

    if (part[0].empty()) {
      std::cerr << "Pattern cannot be empty\n";
      return std::nullopt;
    }
    if (escape) {
      std::cerr << "Trailing backslash in sed rule\n";
      return std::nullopt;
    }
    return SedRule{part[0], part[1], flags};
}

std::string removeEscape(const std::string& input) {
    std::string result;
    bool escape = false;
    for (char c : input) {
        if (escape) {
            result += c;
            escape = false;
        } else if (c == '\\') {
            escape = true;
        } else {
            result += c;
        }
    }
    return result;
}

std::string trim(const std::string& str) {
    
    const auto first = str.find_first_not_of(" \t\r\n");
    const auto last = str.find_last_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    return str.substr(first, (last - first) + 1);
}

std::optional<std::tuple<std::string, std::string, std::string, std::string>> 
parse_auth_to_local(const std::string &rule){
  if (rule.empty()) {

    DEBUG("Empty rule provided");
    return std::nullopt;
  }
  enum State {START, NUMBER, FORMAT, REGEX};
  State state = START;
  std::string prefix = "RULE:[";
  size_t pos = prefix.length();
  std::string number, format, regex_match, sed_rule;
  std::string auth_rule = trim(rule);
  if(auth_rule == "DEFAULT"){
    return std::make_tuple("0", "DEFAULT", "", "");
  }
  else if(auth_rule.rfind(prefix, 0) != 0 ){
    std::cerr << "Invalid rule format: " << auth_rule << "\n";
    return std::nullopt;
  }
  
  state = NUMBER;

  while(pos < auth_rule.length() && isdigit(auth_rule[pos])){
    number += auth_rule[pos];
    pos++;
  }
  if (pos >= auth_rule.length() || (state == NUMBER && auth_rule[pos] != ':')) {
    std::cerr << "Expected ':' at char " << pos << ", got " << auth_rule[pos] << "instead\n";
    return std::nullopt;
  }
  pos++;

  state = FORMAT;
  bool escape = false;
  while (pos < auth_rule.length() && state == FORMAT) {
    char c = auth_rule[pos++];
    if (escape) {
      format += c;
      escape = false;
    } else if (c == '\\') {
      escape = true;
    } else if (c == ']') {
      state = REGEX;
      break;
    } else {
      format += c;
    }
  }
  if(state == REGEX && auth_rule[pos-1] != ']'){
    std::cerr << "Expected ']' at char " << pos << ", got '" << auth_rule[pos-1] << "' instead \n";
    return std::nullopt;
  }
  if(pos>= auth_rule.length() || auth_rule[pos] != '('){

    std::cerr << "Expected '(' at char " << pos+1 << " in "<< auth_rule << "\n";
    std::cerr << "Got " << auth_rule[pos] << " instead\n";
    return std::nullopt;
  }
  pos++;
  escape = false;
  while (pos < auth_rule.length()) {
    char c = auth_rule[pos++];
    if (escape){
      regex_match += c;
      escape = false;
    }
    else if (c == '\\'){
      regex_match += c;
      escape = true;
    } else if (!escape && c == ')'){
      break;
    } else {
      regex_match += c;
    }
  }
  regex_match = process_java_regex_literals(regex_match);
  if (pos < auth_rule.length()){
    sed_rule = auth_rule.substr(pos);
  }
  if (!sed_rule.empty()) {
    sed_rule = process_java_regex_literals(sed_rule);
  }
  return std::make_tuple(
    trim(number), 
    removeEscape(trim(format)), 
    removeEscape(trim(regex_match)), 
    trim(sed_rule));
}

std::vector<std::string> split(const std::string &s, const std::string &delimiter){
  std::vector<std::string> tokens;
  if (s.empty()) {
    return tokens;
  }
  size_t start = 0;
  size_t end = s.find(delimiter);
  
  while (end != std::string::npos) {

    tokens.push_back(s.substr(start, end - start));
    start = end + 1;
    end = s.find(delimiter, start);

  }
  tokens.push_back(s.substr(start));
  return tokens;
}

std::optional<Rule> parse_rule(const std::string &auth_rule){
  if (auth_rule.empty()){
    return std::nullopt;
  }
  std::string trimmed = trim(auth_rule);
  auto auth_to_local = parse_auth_to_local(trimmed);

  if(auth_to_local.has_value()){
    auto [num_fields, format, regex_match_str, sed_rule] = auth_to_local.value();
    if (format != "DEFAULT" && (num_fields.empty() || format.empty() || regex_match_str.empty())) {
      std::cerr << "Invalid rule format: " << auth_rule << "\n";
      return std::nullopt;
    }
    auto sed_cmd = parse_sed_rule(sed_rule);
    Rule rule = 
      {
        .num_fields = std::stoi(num_fields),
        .fmt = format,
        .rule = trim(auth_rule),
        .match_regex = std::regex(trim(regex_match_str), std::regex_constants::ECMAScript),
        .regex_match_string = trim(regex_match_str),
        .sed_rule = parse_sed_rule(sed_rule),
        
      };
    return rule;
  }
  
  DEBUG("Failed to parse rule " << auth_rule);
  return std::nullopt;
}
  
 
int number_of_fields(const std::string &principal) {
  
  if (principal.empty() || principal.find("@") == std::string::npos) {
    std::cerr << "Not a full principal: " << principal << "\n";
    return -1;
  }

  std::string principal_without_realm = principal.substr(0, principal.find("@"));
  std::string::difference_type n = std::count(principal_without_realm.begin(), principal_without_realm.end(), '/');
  int count = static_cast<int>(n);
  // Count is the number of slashes, but we want the actual number of fields separated by the slashes, so one extra.
  return count + 1;
}

std::vector<std::string> extractFields(const std::string &principal){
  if(principal.empty() || principal.find("@") == std::string::npos) {
    std::cerr << "Not a full principal: " << principal << "\n";
    return std::vector<std::string>{};
  }
  return split(principal.substr(0, principal.find("@")), "/");

}

std::string getRealm(std::string principal) {
  if (principal.empty() || principal.find("@") == std::string::npos) {
    std::cerr << "No realm in '" << principal << "'\n";
    return "";
  }
  return std::string(principal.substr(principal.find("@") + 1));
}

int fieldMatch(const Rule &rule, const std::string &principal, std::string &formattedString) {
  if(rule.fmt == "DEFAULT"){
    formattedString = principal;
    return 0;
  }
  int fields = number_of_fields(principal);
  if (rule.num_fields != fields) { 
    if (debug_mode){
    std::cerr << "Number of fields in rule("<<rule.num_fields <<") does not match principal: " << principal << "\n";
    }
    return -1;
  }
  int pos = principal.find("@");
  std::string realm = principal.substr(pos + 1);
  std::vector<std::string> field_values = split(principal.substr(0, pos), "/");
  field_values.insert(field_values.begin(), realm);
  std::optional<std::string> fieldMatchOutput= format(rule.fmt, field_values);
  
  if (fieldMatchOutput.has_value()) {
    formattedString.assign(fieldMatchOutput.value());
    return 0; 
  }
  std::cerr << "Failed to format principal: " << principal << "\n";
  return -1;
}

bool shortRuleMatches(const Rule &rule, const std::string &modified_principal ){
  if (modified_principal.empty()) {
    std::cerr << "Shortened prinicpal is empty\n";
    return false;
  }
  return regex_search(modified_principal, rule.match_regex );
}

int replaceMatchingOutput(const Rule &rule, std::string &modified_principal, std::string &output){
  if(!rule.sed_rule.has_value()){
    output = modified_principal;
    if (debug_mode){
    std::cerr << "No sed rule...\n";
    }
    return 0;
  }

  auto regex_replace_flags = std::regex_constants::format_first_only;
  auto regex_opts = std::regex_constants::ECMAScript;
  bool lowercase_output = false;
  if (! regex_match(modified_principal, rule.match_regex)) {
    if (debug_mode){
    std::cerr << "Modified principal does not match regex: " << modified_principal << "\n";
    std::cerr << "Regex: " << rule.regex_match_string << "\n";
    }
    return -1;
  }
  assert(rule.sed_rule.has_value());
  if (auto sed = rule.sed_rule) {
    if (!sed->flags.empty()){
      if(sed->flags.find("g") != std::string::npos){
        regex_replace_flags = std::regex_constants::match_default;
      }
      if(sed->flags.find("L") != std::string::npos){
        lowercase_output = true;
      }
    }
  }
    

  std::regex match = std::regex(rule.sed_rule.value().pattern, regex_opts);
  output = regex_replace(modified_principal, match, (rule.sed_rule.value().replacement), regex_replace_flags );
  if(lowercase_output) {
    std::transform(output.begin(), output.end(), output.begin(), ::tolower);
  }

  return 0;
}

int transformPrincipal(const Rule &rule, const std::string &principal, std::string &output){
  size_t at_sign_pos = principal.find("@");
  if (principal.empty()) {
    std::cerr << "Principal is empty\n";
    output = "";
    return -1;
  }
  if (at_sign_pos == std::string::npos) {
    std::cerr << "Principal does not contain a realm: " << principal << "\n";
    return -1;
  }
  if (rule.fmt == "DEFAULT"){
    size_t slash_pos = principal.find("/");
    
    if (slash_pos != std::string::npos){
      output = principal.substr(0, slash_pos);
    } else { 
      output = principal.substr(0, at_sign_pos);
    }
    return 0;
  }
  if (rule.num_fields != number_of_fields(principal)) {
    DEBUG("Number of fields in rule(" << rule.num_fields << ") does not match principal: '" << principal << "'");
    output = "";
    return -1;
  }
  int success = fieldMatch(rule, principal, output);
  if (success == 0) {
    
    auto short_success = shortRuleMatches(rule, output);
    if (short_success){
        DEBUG("Successfully matched short rule '" << output << "'");
      int success = replaceMatchingOutput(rule, output, output);
      if (success != 0) {
        DEBUG("Failed to replace matching output for principal: " << principal << " for " << rule.rule);
        output = "";
        return -1;
      }

      return 0;
    }
    else{
      output = "";
      DEBUG("failed to match against shortRuleMatches");
    }

  }
  output = "";
  DEBUG("Failed to match rule " << rule.rule);
  return -1;
}

bool matchPrincipalAgainstRules(const std::vector<Rule> rules, const std::string &principal, std::string &output){
  for (const auto &rule : rules) {
    output.clear();
    if (rule.token_string == "DEFAULT"){
      output = principal;
      return true;
    }
    if (transformPrincipal(rule, principal, output) == 0) {
      DEBUG("Matched against " << rule.rule );
      
      return true;
    }
  }

  return false;
}

