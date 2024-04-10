#pragma once
#ifndef MSPLOGIN_H
#define MSPLOGIN_H

// #includes
#include <string>
// structs

struct Account {
    std::string id;
    std::string sn;
    std::string name;
};

struct MapleLogin {
    std::string id;
    std::string password;
};


// Functions
extern "C" void __declspec(dllexport) getResult_id(char* id);
extern "C" void __declspec(dllexport) getResult_password(char* password);
extern "C" bool __declspec(dllexport) tryGetResult(int which);
extern "C" void __declspec(dllexport) initAccount(const char* bfid, const char* bfpwd);
// End of header file
#endif