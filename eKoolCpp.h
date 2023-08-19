#pragma once
#include <string>
#include <vector>
#include <map>
#include <exception>

#define EKOOL_AUTH_URL "https://login.ekool.eu"

namespace eKool {
    class eKoolError : public std::exception{ //occurs when ekool gives us an error (wrong password for example)
        std::vector<std::string> errors;
        std::string message = "";

    public:
        eKoolError() { }
        eKoolError(std::string msg) { message = msg; }
        eKoolError(std::vector<std::string> err) : errors(err) { for (auto& e : errors) message += e + ","; message = message.substr(0, message.length() - 1); }
        
        const char* what() { return message.c_str(); }
        std::vector<std::string> whatErrs() { return errors; }

    };
    class HTTPError : public std::exception{ //occurs when http gives us an error (no internet connection for example)
    private:
        char error;
        std::string message;

    public:
        HTTPError(char err);

        const char* what() { return message.c_str(); }
        char whatError() { return error; }

    };

    struct User{
    public:
        /**
         * @brief Init the user
         * 
         * @param cookies Cookies from login
         * @param url Where login redirects you
         * @param allowExceptions Throw exceptions or not
         * @return True on success
         * @throw HTTPError with an error code and description
         * @throw eKoolError with a string
        */
        bool Init(std::map<std::string, std::string> cookies, std::string url, bool allowExceptions);

        /**
         * @brief Get user's name
         * 
         * @param allowExceptions Throw exceptions or not
         * @return First & second name on success, empty strings when failed
         * @throw HTTPError with an error code and description
         * @throw eKoolError with a string
        */
        std::pair<std::string, std::string> GetName(bool allowExceptions = true);

    private:
        std::map<std::string, std::string> m_cookies;
        std::string m_url = "";
        std::string m_scriptSession = "";

    };

    /**
     * @brief Login using password
     * 
     * @param username Username of the user
     * @param password Password of the user
     * @param allowExceptions Throw exceptions or not
     * @return User on success, NULL otherwise
     * @throw HTTPError with an error code and description
     * @throw eKoolError: Vector of errors returned by eKool or a string from Init
     */
    User* LoginPass(std::string username, std::string password, bool allowExceptions = true);

    /**
     * @brief Login using Mobile-ID (UNSUPPORTED RIGHT NOW)
     * 
     * @param personalCode Personal code of the user
     * @param phoneNumber Phone number of the user
     * @param allowExceptions Throw exceptions or not
     * @return User on success, NULL otherwise
     * @throw HTTP error code and description
     * @throw Vector of errors returned by eKool
     */
    User* LoginMobileID(std::string personalCode, std::string phoneNumber, bool allowExceptions = true);
    
    /**
     * @brief Login using Smart-ID (UNSUPPORTED RIGHT NOW)
     * 
     * @param country Country code of the user ("EE", "LV" or "LT")
     * @param personalCode Personal code of the user
     * @param allowExceptions Throw exceptions or not
     * @return User on success, NULL otherwise
     * @throw HTTP error code and description
     * @throw Vector of errors returned by eKool
     */
    User* LoginSmartID(std::string country, std::string personalCode, bool allowExceptions = true);
}