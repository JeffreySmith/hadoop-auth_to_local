#include <token.h>
#include <rule.h>
#include <iostream>
#include <assert.h>
#include <debug.h>
#include <coresite.h>
#include <getopt.h>
bool debug_mode = false;

int main(int argc, char **argv){

  std::string testing_rule = R"(s/foo\/bar/baz\/qux/gL)";
  std::optional<SedRule> parsed = parse_sed_rule(testing_rule);
  assert(parsed.has_value());
  assert(parsed.value().pattern == "foo/bar");
  assert(parsed.value().replacement == "baz/qux");
  assert(parsed.value().flags == "gL");

  parsed = parse_sed_rule(R"(s|[foo]|bar|)");
  assert(parsed.has_value());
  assert(parsed.value().pattern == "[foo]");
  assert(parsed.value().replacement == "bar");
  


  std::string my_matching_principal = "hdfs-rangerkerberos@ADSRE.COM";
  std::string filepath = "./core-site.xml";
  bool extra_tests = false;
  int opt;
  static struct option long_options[] = {
    {"debug", no_argument, nullptr, 'd'},
    {"file", required_argument, nullptr, 'f'},
    {"principal", required_argument, nullptr, 'p'},
    {"tests", no_argument, nullptr, 't'},
    {0, 0, 0, 0}
  };
  while ((opt = getopt_long(argc, argv, "tdf:p:", long_options, NULL)) != -1){
    switch(opt){
      case 'd':
        debug_mode = true;
        break;
      case 't':
        extra_tests = true;
        break;
      case 'f':
        filepath = optarg;
        if (optarg) {
          filepath = optarg;
        } else {
          std::cerr << "Option -f requires an argument.\n";
          return 1;
        }
        break;
      case 'p':
        if (optarg) {
          my_matching_principal = optarg;
        } else {
          std::cerr << "Option -p requires an argument.\n";
          return 1;
        }
        break;
      default:
        std::cerr << "Usage: " << argv[0] << " [-d --debug] [-f --file <file>] [-p --principal <principal>]\n";
        return 1;
    }
  }
  
  DEBUG("Debug mode enabled");
  basic_token_test();
  auto rule = parse_rule("RULE:[2:$1@$0](spark-rangerkerberos@ADSRE.COM)s/.*/spark/   ");
  auto rule_one_part = parse_rule(R"(RULE:[1:$1@$0](spark-rangerkerberos@ADSRE.COM)s/.*/spark/)");
  
  std::string out = "";
  assert(rule_one_part.has_value());
  assert(rule_one_part.value().num_fields == 1);
  transformPrincipal(rule_one_part.value(), "spark-rangerkerberos@ADSRE.COM", out);
  
  assert(out == "spark");
  auto default_rule = parse_rule("DEFAULT");
  assert(default_rule.has_value());

  assert(rule.has_value());
  assert(3 == number_of_fields("kudu/ho/st@ADSRE.COM"));
  assert(1 == number_of_fields("kudu@ADSRE.COM"));
  
  std::string output = "";
  int matched = fieldMatch(rule.value(), "spark-rangerkerberos/my_host@ADSRE.COM", output);
  assert(matched == 0);
  assert(output.length() > 0);
  
  std::string transform_output = "";
  int success = replaceMatchingOutput(rule.value(), output,transform_output);
  assert(success == 0);
  assert(transform_output == "spark");
 
  int not_matched = fieldMatch(rule.value(), "spark-rangerkerberos@ADSRE.COM", output);
  assert(not_matched != 0);
  assert(shortRuleMatches(rule.value(), output));
  output = "ANYTHING@ACCELDATA.IO";
  assert(shortRuleMatches(default_rule.value(), output));
  
  std::vector<std::string> all_rules = loadRules(filepath);// split(load_auth_rules(filepath), "\n");
  assert(all_rules.size() > 0);
  
  std::vector<Rule> all_rules_parsed;
  for (const auto &r : all_rules){
    if (r.empty()){
      continue;
    }
    auto new_rule = parse_rule(r);
    if (new_rule.has_value()) {
      all_rules_parsed.push_back(new_rule.value());
    }
    else{
      DEBUG("Failed to parse rule: " << r );
    }
  }
  DEBUG("\n\n\n");
  DEBUG("Trying against whole list");
  DEBUG("Principal is: " << my_matching_principal );
  if(matchPrincipalAgainstRules(all_rules_parsed, my_matching_principal, output) == true){
    std::cout << my_matching_principal << " transformed into " << output << "\n";
  } else {
    std::cerr << "No matching rule found for '" << my_matching_principal << "'\n";
  }
  
  
}
