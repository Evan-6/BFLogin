#include "Login.h"
//mkexp MSPLoginBCB.lib MSPLogin.dll vc dll to bcb lib
//what is clean code OAO
cpr::Session session;
cpr::Payload payloadempty{};
cpr::Response response;
string t_AccountID;
string t_Password;
string loginUrl = "https://tw.beanfun.com/beanfun_block/bflogin/default.aspx";
string f, skey, akey, bfWebToken;
string screatetime, lpk, m_strSecretCode, dt, url, newscreatetime;
string viewstate, viewstategenerator, eventvalidation;
vector<Account> accounts;
Account account;
MapleLogin MapleResult;
vector<uint8_t> hexStringToBytes(const string& hexString) {
    vector<uint8_t> bytes;
    for (string::size_type i = 0; i < hexString.length(); i += 2) {
        string byteString = hexString.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

string decrypt_str(const string& key, const string& data) {
    vector<uint8_t> keyBytes = hexStringToBytes(key);
    vector<uint8_t> dataBytes = hexStringToBytes(data);
    DES_cblock keyDes;
    memcpy(keyDes, keyBytes.data(), 8);
    DES_key_schedule keySchedule;
    DES_set_key(&keyDes, &keySchedule);

    vector<uint8_t> outputBytes(dataBytes.size());
    vector<uint8_t> inputBlock(8);
    vector<uint8_t> outputBlock(8);
    for (vector<uint8_t>::size_type i = 0; i < dataBytes.size(); i += 8) {
        memcpy(inputBlock.data(), &dataBytes[i], 8);
        DES_ecb_encrypt((DES_cblock*)inputBlock.data(),
            (DES_cblock*)outputBlock.data(), &keySchedule, DES_DECRYPT);
        memcpy(&outputBytes[i], outputBlock.data(), 8);
    }
    return string(outputBytes.begin(), outputBytes.end());
}
string get_value_from_string(const string& str, const string& key) {
    regex pattern(key + "=([^&]*)(&|$)");
    smatch result;
    if (regex_search(str, result, pattern)) {
        //cout << "FOUND : " << result[1] << endl;
        return result[1];
    }
    //cout << "NOT FOUND : " << endl;
    return "";
}

void parseAccounts(string text) {
    regex pattern(
        "<div +id=\"([^\"]*)\" +sn=\"([^\"]*)\" "
        "+name=\"([^\"]*)\"[^>]*>[^<]*</div>");
    smatch matches;
    while (regex_search(text, matches, pattern)) {
        Account account = { matches[1], matches[2], matches[3] };
        accounts.push_back(account);
        text = matches.suffix().str();
    }
}

Account getAccount(int n) { return accounts[n - 1]; }
void initAccount(const char* bfid, const  char* bfpwd) {
    t_AccountID = bfid;
    t_Password = bfpwd;
}
void login() {
    session.SetPayload(payloadempty);
    session.SetUrl(cpr::Url{ loginUrl });
    session.SetHeader(cpr::Header{ {"User-Agent",
                                   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                                   "Chrome/94.0.4606.61 Safari/537.36"} });
    cpr::Response loginHtml = session.Get();
    f = loginHtml.url.c_str();

    // 從返回的響應中獲取 skey
    skey = get_value_from_string(f, "skey");
    //cout << skey << endl;
    // 訪問登入頁面，獲取表單數據
    session.SetUrl(
        cpr::Url{ "https://tw.newlogin.beanfun.com/login/id-pass_form.aspx?skey=" +
                 skey + "&clientID=undefined" });
    cpr::Response loginHtml2 = session.Get();
    //cout << loginHtml2.text << endl;
    regex regex_viewstate("id=\"__VIEWSTATE\" value=\"(.*)\"");
    regex regex_viewstategenerator("id=\"__VIEWSTATEGENERATOR\" value=\"(.*)\"");
    regex regex_eventvalidation("id=\"__EVENTVALIDATION\" value=\"(.*)\"");

    smatch match_viewstate, match_viewstategenerator, match_eventvalidation;
    regex_search(loginHtml2.text, match_viewstate, regex_viewstate);
    regex_search(loginHtml2.text, match_viewstategenerator,
        regex_viewstategenerator);
    regex_search(loginHtml2.text, match_eventvalidation, regex_eventvalidation);

    viewstate = match_viewstate[1];
    viewstategenerator = match_viewstategenerator[1];
    eventvalidation = match_eventvalidation[1];
    //cout << "------------------------------------------" << endl;
    //cout << viewstate << endl;
    //cout << viewstategenerator << endl;
    //cout << eventvalidation << endl;

    // 更新表單數據

    //form_data = { {"__EVENTTARGET", ""},
    //             {"__EVENTARGUMENT", ""},
    //             {"__VIEWSTATE", viewstate},
    //             {"__VIEWSTATEGENERATOR", viewstategenerator},
    //             {"__EVENTVALIDATION", eventvalidation},
    //             {"t_AccountID", t_AccountID},
    //             {"t_Password", t_Password},
    //             {"btn_login", "登入"} };
    //for (const auto& kv : form_data) {
    //    //cout << kv.first << " : " << kv.second << endl;
    //}
    // 發送 POST 請求，進行登入操作
    cpr::Payload payload{ {"__EVENTTARGET", ""},
                         {"__EVENTARGUMENT", ""},
                         {"__VIEWSTATE", viewstate},
                         {"__VIEWSTATEGENERATOR", viewstategenerator},
                         {"__EVENTVALIDATION", eventvalidation},
                         {"t_AccountID", t_AccountID},
                         {"t_Password", t_Password},
                         {"btn_login", "登入"} };
    session.SetPayload(payload);
    session.SetUrl(
        cpr::Url{ "https://tw.newlogin.beanfun.com/login/id-pass_form.aspx?skey=" +
                 skey + "&clientID=undefined" });
    response = session.Post();
    //cout << response.text << endl;
    for (const auto& cookie : response.cookies) {
        // cout << cookie.GetDomain() << ":";
        // cout << cookie.IsIncludingSubdomains() << ":";
        // cout << cookie.GetPath() << ":";
        // cout << cookie.IsHttpsOnly() << ":";
        // cout << cookie.GetExpiresString() << ":";
        //cout << cookie.GetName() << ":";
        //cout << cookie.GetValue() << endl;
        // For example, this will print:
        // www.httpbin.org:0:/:0:Thu, 01 Jan 1970 00:00:00 GMT:cookies:yummy
        if (cookie.GetName() == "bfWebToken") bfWebToken = cookie.GetValue();
    }
    f = response.url.c_str();
    //cout << f << endl;
    akey = get_value_from_string(f, "akey");
    //cout << akey << endl;
    cpr::Payload payload2{
        {"SessionKey", skey},  {"AuthKey", akey},         {"ServiceCode", ""},
        {"ServiceRegion", ""}, {"ServiceAccountSN", "0"},
    };
    session.SetPayload(payload2);
    session.SetUrl(
        cpr::Url{ "https://tw.beanfun.com/beanfun_block/bflogin/return.aspx" });
    response = session.Post();
    session.SetUrl(
        cpr::Url{ "https://tw.beanfun.com/beanfun_block/"
                 "auth.aspx?channel=game_zone&page_and_query=game_start.aspx%"
                 "3Fservice_code_and_region%3D610074_T9&web_token=" +
                 bfWebToken });
    response = session.Get();
    f = response.url.c_str();
    dt = get_value_from_string(f, "dt");
    //cout << dt << endl;
}
int getAccountHtml() {
    session.SetPayload(payloadempty);
    session.SetUrl(
        cpr::Url{ "https://tw.beanfun.com/beanfun_block/game_zone/"
                 "game_server_account_list.aspx?sc=610074&sr=T9&dt=" +
                 dt });
    response = session.Get();
    if (string(response.url.c_str()).find(string("LOGIN-UNLOGIN_IN_PLEASE_LOGIN")) != std::string::npos) {
        //cout << "Get Account Html Fail" << endl;
        return 0;

    }
    accounts.clear();
    parseAccounts(response.text);
    return 1;
    // cout << response.text << endl;

    //cout << "id: " << account.id << endl;
    //cout << "sn: " << account.sn << endl;
    //cout << "name: " << account.name << endl;
}
int getpwd(int which) {
    try {
        account = getAccount(which);
        session.SetUrl(cpr::Url{
            "https://tw.beanfun.com/beanfun_block/game_zone/"
            "game_start_step2.aspx?service_code=610074&service_region=T9&sotp=" +
            account.sn + "&dt=" + dt });
        response = session.Get();
        if (string(response.url.c_str()).find(string("err_page")) != std::string::npos) {
            cout << "game_start Fail" << endl;
            return 0;

        }
        regex screatetime_re("ServiceAccountCreateTime: \"([^\"]*)");
        smatch match;

        if (regex_search(response.text, match, screatetime_re)) {
            screatetime = match[1].str();
            //cout << "ServiceAccountCreateTime: " << screatetime << endl;
        }
        else {
            //cout << "No match found." << endl;
        }
        regex lpk_re("GetResultByLongPolling&key=([^&\"]+)");
        if (regex_search(response.text, match, lpk_re)) {
            lpk = match[1].str();
            //cout << "GetResultByLongPolling: " << lpk << endl;
        }
        else {
            //cout << "No match found." << endl;
        }
        session.SetPayload(payloadempty);
        session.SetUrl(cpr::Url{
            "https://tw.newlogin.beanfun.com/generic_handlers/get_cookies.ashx" });
        response = session.Get();
        regex m_strSecretCode_re("var m_strSecretCode = '([^']+)';");
        if (regex_search(response.text, match, m_strSecretCode_re)) {
            m_strSecretCode = match[1].str();
            //cout << "m_strSecretCode: " << m_strSecretCode << endl;
        }
        else {
            //cout << "No match found." << endl;
        }
        /*cpr::Payload record_data = {
        {"service_code", "610074"},
        {"service_region", "T9"},
        {"service_account_id", account.id},
        {"sotp", account.sn},
        {"service_account_display_name", account.name},
        {"service_account_create_time", screatetime}
        };
        session.SetPayload(record_data);
        session.SetUrl(cpr::Url{
          "https://tw.beanfun.com/beanfun_block/generic_handlers/record_service_start.ashx"
            });
        response = session.Post();
        cout << response.text << endl;*/
        // string Ref =
        // "https://tw.beanfun.com/beanfun_block/game_zone/game_start_step2.aspx?service_code=610074&service_region=T9&sotp="
        // + account.sn + "&dt=" + dt;
        // session.SetHeader(cpr::Header{
        //  {
        //    "User-Agent",
        //    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,
        //    like Gecko) Chrome/94.0.4606.61 Safari/537.36"
        //  }//,{"Referer",Ref}
        //
        //    });
        newscreatetime = "";
        for (int i = 0; i < screatetime.length(); i++) {
            if (screatetime[i] == ' ') {
                newscreatetime += "%20";
            }
            else {
                newscreatetime += screatetime[i];
            }
        }
        url =
            "https://tw.beanfun.com/beanfun_block/generic_handlers/"
            "get_webstart_otp.ashx";
        url += "?SN=" + lpk;
        url += "&WebToken=" + bfWebToken;
        url += "&SecretCode=" + m_strSecretCode;
        url +=
            "&ppppp=1F552AEAFF976018F942B13690C990F60ED01510DDF89165F1658CCE7BC21DBA";
        url += "&ServiceCode=610074&ServiceRegion=T9&ServiceAccount=" + account.id;
        url += "&CreateTime=" + newscreatetime + "&d=" + to_string(time(nullptr));
        session.SetPayload(payloadempty);
        session.SetUrl(url);
        response = session.Get();
        //cout << response.text << endl;
        //cout << response.text.substr(2, 8).c_str() << endl;
        //cout << response.text.substr(10, 32).c_str() << endl;
        string key = response.text.substr(2, 8).c_str();
        string data = response.text.substr(10, 32).c_str();
        DES_cblock key_cblock;
        DES_key_schedule key_schedule;
        memcpy(key_cblock, key.c_str(), 8);
        DES_set_key_unchecked(&key_cblock, &key_schedule);
        string decrypted;
        for (size_t i = 0; i < data.size(); i += 16) {
            string block = data.substr(i, 16);
            DES_cblock block_cblock;
            for (size_t j = 0; j < 8; ++j) {
                block_cblock[j] = stoi(block.substr(j * 2, 2), nullptr, 16);
            }
            DES_cblock decrypted_block;
            DES_ecb_encrypt(&block_cblock, &decrypted_block, &key_schedule,
                DES_DECRYPT);
            decrypted += string(reinterpret_cast<char*>(decrypted_block), 8);
        }
        //cout << account.id << endl;
        //cout << decrypted << endl;
        MapleResult.id = account.id;
        MapleResult.password = decrypted;
        return 1;
    }
    catch (...) {
        return 0;
    }
    // session.SetHeader(cpr::Header{
    //  {
    //    "User-Agent",
    //    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,
    //    like Gecko) Chrome/94.0.4606.61 Safari/537.36"
    //  }
    //    });
}
bool tryGetResult(int which) {
    if (getAccountHtml()) {
        if (getpwd(1)) {
            return 1;
        }
        else {
            //cout << "getpwd error" << endl;
            login();
            if (getAccountHtml()) {
                if (getpwd(which)) {
                    return 1;
                }
                else {
                    return 0;
                    //cout << "getpwd error" << endl;
                }
            }
        }
    }
    else {
        login();
        if (getAccountHtml()) {
            if (getpwd(which)) {
                return 1;
            }
            else {
                return 0;
                //cout << "getpwd error" << endl;
            }
        }
        else {
            return 0;
            //cout << "Login error" << endl;
        }
    }
    return 0;
}
void getResult_id(char* id) {
    strcpy(id, MapleResult.id.c_str());
}
void getResult_password(char* password) {
    strcpy(password, MapleResult.password.c_str());
}


