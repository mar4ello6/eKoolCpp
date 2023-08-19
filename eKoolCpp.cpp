#include "eKoolCpp.h"
#include <cstdio>
#include <nlohmann/json.hpp>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

std::string GetCookieString(std::map<std::string, std::string> cookies){
    std::string result = "";
    for (auto& c : cookies){
        if (result != "") result += "; ";
        result += c.first + "=" + httplib::detail::encode_url(c.second);
    }
    return result;
}

void AddCookies(std::map<std::string, std::string>& cookies, httplib::Headers headers){
    for (auto& h : headers){ //retrieving cookies
        if (h.first != "set-cookie") continue;

        size_t nameDelim = h.second.find('=');
        cookies[h.second.substr(0, nameDelim)] = h.second.substr(nameDelim + 1, h.second.find(';', nameDelim) - nameDelim - 1);
    }
}

eKool::HTTPError::HTTPError(char err) : error(err) {
    message = httplib::to_string((httplib::Error)error);
}

bool eKool::User::Init(std::map<std::string, std::string> cookies, std::string url, bool allowExceptions){
    m_cookies = cookies;

    //set user, we get 'AUTH' cookie here
    size_t pathStart = url.find('/', 8); //hardcoding it to skip https://
    if (pathStart == std::string::npos){ //something is terribly wrong
        if (allowExceptions) throw eKoolError("no_login_url");
        return false;
    }
    httplib::Client cli(url.substr(0, pathStart));
    httplib::Headers headers = {
        {"Cookie", GetCookieString(m_cookies)}
    };
    auto res = cli.Get(url.substr(pathStart), headers);
    if (!res) {
        if (allowExceptions) throw HTTPError((char)res.error());
        return false;
    }
    AddCookies(m_cookies, res->headers);
    if (res->headers.find("location") != res->headers.end()) {
        m_url = res->headers.find("location")->second;
        size_t urlPathStart = m_url.find('/', 8); //skipping https:// here too
        m_url = m_url.substr(0, urlPathStart);
    }

    if (m_url != "https://family.ekool.eu"){ //parents (and probably teachers) have a bit different algorithm of logging in
        if (allowExceptions) throw eKoolError("not_student");
        return false;
    }

    httplib::Client idCli(m_url);
    headers = {
        {"Cookie", GetCookieString(m_cookies)}
    };
    res = idCli.Post("/dwr/call/plaincall/__System.generateId.dwr", headers, "callCount=1\nc0-scriptName=__System\nc0-methodName=generateId\nc0-id=0\nbatchId=0\ninstanceId=0\npage=%2Findex_et.html\nscriptSessionId=\n", "text/plain");
    if (!res) {
        if (allowExceptions) throw HTTPError((char)res.error());
        return false;
    }
    if (res->status != 200) {
        if (allowExceptions) throw eKoolError("generateId_status_" + std::to_string(res->status));
        return false;
    }
    AddCookies(m_cookies, res->headers);
    size_t tokenFunc = res->body.find("dwr.engine.remote.handleCallback(\"0\",\"0\",\"");
    if (tokenFunc == std::string::npos) {
        if (allowExceptions) throw eKoolError("no_generateId");
        return false;
    }
    m_cookies["DWRSESSIONID"] = res->body.substr(tokenFunc + 42, res->body.find('\"', tokenFunc + 42) - tokenFunc - 42);
    m_scriptSession = m_cookies["DWRSESSIONID"] + "/VmZGHXl-*4zGFcRyl"; //thing that we add is _pageId from c.js, it's static in file for some reason

    return true;
}

std::pair<std::string, std::string> eKool::User::GetName(bool allowExceptions){
    std::pair<std::string, std::string> names = {"", ""};
    httplib::Client cli(m_url);
    httplib::Headers headers = {
        {"Cookie", GetCookieString(m_cookies)}
    };
    auto res = cli.Post("/dwr/call/plaincall/userAccountManager.getSessData.dwr", headers, "callCount=1\nnextReverseAjaxIndex=0\nc0-scriptName=userAccountManager\nc0-methodName=getSessData\nc0-id=0\nbatchId=0\ninstanceId=0\npage=%2Findex_et.html\nscriptSessionId=" + m_scriptSession + "\n", "text/plain");
    if (!res){
        if (allowExceptions) throw HTTPError((char)res.error());
        return names;
    }
    if (res->status != 200){
        if (allowExceptions) throw eKoolError("status_" + std::to_string(res->status));
        return names;
    }

    //getting name of var with names
    size_t varNamePosEnd = res->body.find("=new ee.ekool.model.Person();");
    size_t varNameStart = res->body.rfind("var ", varNamePosEnd);
    if (varNamePosEnd == std::string::npos || varNameStart == std::string::npos){
        if (allowExceptions) throw eKoolError("no_person");
        return names;
    }
    varNameStart += 4;
    std::string varName = res->body.substr(varNameStart, varNamePosEnd - varNameStart);

    //getting names
    size_t firstNameStart = res->body.find(varName + ".name1=\"");
    size_t secondNameStart = res->body.find(varName + ".name2=\"");
    if (firstNameStart == std::string::npos || secondNameStart == std::string::npos){
        if (allowExceptions) throw eKoolError("no_person");
        return names;
    }
    firstNameStart += 10;
    secondNameStart += 10;
    names.first = res->body.substr(firstNameStart, res->body.find("\";", firstNameStart) - firstNameStart);
    names.second = res->body.substr(secondNameStart, res->body.find("\";", secondNameStart) - secondNameStart);

    return names;
}

eKool::User* eKool::LoginPass(std::string username, std::string password, bool allowExceptions){
    httplib::Client cli(EKOOL_AUTH_URL);

    auto res = cli.Get("/"); //getting root page first, needed for cookies (it gives us token and session)
    if (!res) {
        if (allowExceptions) throw HTTPError((char)res.error());
        return NULL;
    }
    std::map<std::string, std::string> cookies;
    AddCookies(cookies, res->headers);
    
    httplib::Params params;
    params.emplace("email", username);
    params.emplace("password", password);
    params.emplace("recaptcha", "");
    params.emplace("two_factor_code", "");
    httplib::Headers headers = {
        {"Cookie", GetCookieString(cookies)},
        {"X-Requested-With", "XMLHttpRequest"}
    };
    res = cli.Post("/login", headers, params);
    if (!res) {
        if (allowExceptions) throw HTTPError((char)res.error());
        return NULL;
    }

    if (res->status == 200){ //success
        AddCookies(cookies, res->headers);
        bool success = false;
        std::string url = "";
        try {
            nlohmann::json j = nlohmann::json::parse(res->body);
            success = j["success"];
            url = j["url"];
        } catch (...) {}

        if (!success){ //this shouldn't happen, but... who knows what can happen here
            if (allowExceptions) throw eKoolError();
            return NULL;            
        }

        User* user = new User;
        if (!user->Init(cookies, url, allowExceptions)){
            delete user;
            return NULL;
        }
        return user;
    }
    else { //failed, we'll try to get the error
        if (allowExceptions){
            std::vector<std::string> errors;
            try {
                errors = nlohmann::json::parse(res->body)["errors"].get<std::vector<std::string>>();
            } catch (...) {}
            throw eKoolError(errors);
        }
        return NULL;
    }

    return NULL;
}

eKool::User* eKool::LoginMobileID(std::string personalCode, std::string phoneNumber, bool allowExceptions){
    return NULL;
}

eKool::User* eKool::LoginSmartID(std::string country, std::string personalCode, bool allowExceptions){
    return NULL;
}