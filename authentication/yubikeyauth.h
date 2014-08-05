/*
 * NotesDrive Server: Encrypted remote note storage.
 * Copyright (C) 2014  Deadb4t Deadb4t@googlemail.com
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#ifndef YUBIKEYAUTH_H
#define YUBIKEYAUTH_H

#include <string>
#include <map>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

struct YubiKeyStatus
{
    std::string Name;
    std::string Meaning;
};

class YubiKeyAuth
{
    public:
        YubiKeyAuth();
        void InitStatusList();
        bool VerifyOTP(std::string yubiKeyOTP);
        std::string GetYubiKeyUID(std::string yubiKeyOTP);
        YubiKeyStatus AuthenticateOTP(std::string yubiKeyOTP);
        
        void PrintYubiStatus(YubiKeyStatus status);
        
        void SetAuthURL(std::string authURL);
        std::string GetAuthURL();
        
        // K: Name, V: Meaning
        std::map<std::string, std::string> YKStatusList;
        
    private:
        boost::asio::ip::tcp::socket* SendAuthRequest(std::string yubiKeyOTP);
        std::string MakeRequestData(std::string yubiKeyOTP);
        std::string MakeNonce();
        
        std::string GetAuthResponse(boost::asio::ip::tcp::socket* s);
        bool CheckResponse(boost::asio::streambuf &response);
        YubiKeyStatus GetStatusFromResponse(std::string responseData);
        
        std::string ClientAPIID;
        std::string APISecret;
        
        std::string AuthURL;
        std::string AuthHostName;
        std::string AuthPath;
        
};

#endif // YUBIKEYAUTH_H
