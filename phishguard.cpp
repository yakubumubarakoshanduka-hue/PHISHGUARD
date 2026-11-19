// PhishGuard console version. Build: g++ -std=c++17 phishguard.cpp -o phishguard
#include <algorithm>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace std;

struct Brand { string name, token, domain; };
const vector<Brand> BRANDS = {
  {"GTBank","gtbank","gtbank.com"},{"Access Bank","accessbank","accessbankplc.com"},
  {"Zenith Bank","zenith","zenithbank.com"},{"First Bank","firstbank","firstbanknigeria.com"},
  {"UBA","uba","ubagroup.com"},{"Opay","opay","opay.com"},{"CBN","cbn","cbn.gov.ng"},
  {"FIRS","firs","firs.gov.ng"},{"NIMC","nimc","nimc.gov.ng"},{"JAMB","jamb","jamb.gov.ng"},
  {"MTN","mtn","mtn.ng"},{"UNILAG","unilag","unilag.edu.ng"},
  {"NSUK Keffi","nsuk","nsuk.edu.ng"},{"University of Abuja","uniabuja","uniabuja.edu.ng"},
  {"University of Ilorin","unilorin","unilorin.edu.ng"},{"University of Jos","unijos","unijos.edu.ng"},
  {"FUT Minna","futminna","futminna.edu.ng"},{"IBB University","ibbu","ibbu.edu.ng"},
  {"Federal University Lafia","fulafia","fulafia.edu.ng"},{"UDUS","udusok","udusok.edu.ng"},
  {"Jaiz Bank","jaiz","jaizbankplc.com"},{"INEC","inecnigeria","inecnigeria.org"}};
const vector<string> WORDS = {"login","verify","secure","update","confirm","bvn","otp","password","suspend","bonus","claim","portal"};

string lower(string s){ transform(s.begin(), s.end(), s.begin(), ::tolower); return s; }
string hostOf(string u){
  size_t p = u.find("://"); if (p != string::npos) u = u.substr(p + 3);
  u = u.substr(0, u.find_first_of("/?#")); size_t at = u.rfind('@');
  if (at != string::npos) u = u.substr(at + 1);
  return u.substr(0, u.find(':'));
}
bool endsWith(const string& s, const string& e){ return s.size() >= e.size() && s.compare(s.size()-e.size(), e.size(), e) == 0; }

int main(){
  cout << "=== PhishGuard Nigeria (console) ===\nType a URL, or 'q' to quit.\n";
  string line;
  while (cout << "\nURL> " && getline(cin, line)) {
    if (line == "q") break;
    if (line.empty() || line.find(' ') != string::npos) { cout << "Enter a single valid URL.\n"; continue; }
    string url = lower(line), host = hostOf(url);
    if (host.find('.') == string::npos) { cout << "Invalid address.\n"; continue; }
    int score = 0; vector<string> why; bool official = false;
    for (auto& b : BRANDS) if (host == b.domain || endsWith(host, "." + b.domain)) official = true;
    if (!official) {
      if (url.rfind("https://", 0) != 0) { score += 12; why.push_back("No HTTPS"); }
      if (url.find('@') != string::npos) { score += 25; why.push_back("Contains '@'"); }
      if (count(host.begin(), host.end(), '-') >= 2) { score += 10; why.push_back("Many hyphens"); }
      if (all_of(host.begin(), host.end(), [](char c){ return isdigit(c) || c == '.'; })) { score += 35; why.push_back("IP address host"); }
      for (auto& tld : {".xyz",".top",".tk",".click",".icu",".buzz"}) if (endsWith(host, tld)) { score += 15; why.push_back("Risky extension"); }
      for (auto& w : WORDS) if (url.find(w) != string::npos) { score += 5; why.push_back("Keyword: " + w); }
      for (auto& b : BRANDS) if (host.find(b.token) != string::npos) { score += 45; why.push_back("Impersonates " + b.name); break; }
    }
    score = min(score, 100);
    string verdict = score >= 60 ? "PHISHING" : score >= 30 ? "SUSPICIOUS" : "SAFE";
    cout << verdict << " (risk " << score << "/100)\n";
    for (auto& w : why) cout << " - " << w << "\n";
    ofstream("history.txt", ios::app) << time(nullptr) << "," << line << "," << verdict << "\n";
  }
  return 0;
}
