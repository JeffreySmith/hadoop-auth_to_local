#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/foreach.hpp>
#include <string>
#include <iostream>
#include <fstream>
#include <rule.h>
#include <vector>
#include <algorithm>

namespace pt = boost::property_tree;

std::string load_auth_rules(const std::string &filename){

  std::string default_rules = "RULE:[1:$1@$0](.*@ADSRE.COM)s/@.*//\nDEFAULT";
  std::ifstream file(filename);
  if(file.good()){
    pt::ptree tree;
    pt::read_xml(filename, tree);

    for (const auto &property : tree.get_child("configuration")){

      if(property.first == "property") {
        std::string name = property.second.get<std::string>("name", default_rules);
        if (name == "hadoop.security.auth_to_local") {
          return property.second.get<std::string>("value", default_rules);
        }
      }
    }  
  }
  
  std::cerr << "Warning: Using default rules since no user readable file was passed\n";
  return default_rules;
}
std::vector<std::string> loadRules(const std::string &filepath) {
  std::vector<std::string> rules = split(load_auth_rules(filepath), "\n");
  rules.erase(std::remove_if(rules.begin(), rules.end(), [](const std::string &s) {
    return trim(s).empty() ; 
  }), rules.end());

  return rules;
}


