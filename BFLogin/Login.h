#pragma once
#ifndef MSPLOGIN_H
#define MSPLOGIN_H

// #includes
#include "framework.h"
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <cpr/cpr.h>
#include <openssl/des.h>
#pragma warning(disable : 4996)
#pragma comment( lib, "ws2_32.lib" )
#pragma comment( lib, "Crypt32.lib" )
using namespace std;
// structs

struct Account {
    std::string id;
    string sn;
    string name;
};

struct MapleLogin {
    string id;
    string password;
};


// Functions

Account getAccount(int n);
extern "C" void __declspec(dllexport) getResult_id(char* id);
extern "C" void __declspec(dllexport) getResult_password(char* password);
extern "C" bool __declspec(dllexport) tryGetResult(int which);
extern "C" void __declspec(dllexport) initAccount(const char* bfid, const char* bfpwd);
int getAccountHtml();
int getpwd(int which);
string decrypt_str(const string& key, const string& data);
string get_value_from_string(const string& str, const string& key);
void login();
void parseAccounts(string text);

// End of header file
#endif