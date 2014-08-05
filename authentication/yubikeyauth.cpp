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

#include "yubikeyauth.h"

#include <iostream>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <map>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

using namespace std;
using namespace boost::asio::ip;

YubiKeyAuth::YubiKeyAuth()
{
    AuthURL = "api.yubico.com/wsapi/2.0/verify";
    AuthHostName = "api.yubico.com";
    AuthPath = "/wsapi/2.0/verify";
    ClientAPIID = "17648";
    InitStatusList();
}
void YubiKeyAuth::InitStatusList()
{
    YKStatusList.insert(pair<string, string>("OK", "The OTP is valid."));
    YKStatusList.insert(pair<string, string>("BAD_OTP", "The OTP is invalid format."));
    YKStatusList.insert(pair<string, string>("REPLAYED_OTP", "The OTP has already been seen by the service."));
    YKStatusList.insert(pair<string, string>("BAD_SIGNATURE", "The HMAC signature verification failed."));
    YKStatusList.insert(pair<string, string>("MISSING_PARAMETER", "The request lacks a parameter."));
    YKStatusList.insert(pair<string, string>("NO_SUCH_CLIENT", "The request id does not exist."));
    YKStatusList.insert(pair<string, string>("OPERATION_NOT_ALLOWED", "The request id is not allowed to verify OTPs."));
    YKStatusList.insert(pair<string, string>("BACKEND_ERROR", "Unexpected error in our server. Please contact us if you see this error."));
    YKStatusList.insert(pair<string, string>("NOT_ENOUGH_ANSWERS", "Server could not get requested number of syncs during before timeout."));
    YKStatusList.insert(pair<string, string>("REPLAYED_REQUEST", "Server has seen the OTP/Nonce combination before."));
}

bool YubiKeyAuth::VerifyOTP(std::string yubiKeyOTP)
{
    if(yubiKeyOTP.length() >= 32 && yubiKeyOTP.length() <= 48)
    {
        return true;
    }
    else
    {
        return false;
    }
}

std::string YubiKeyAuth::GetYubiKeyUID(std::string yubiKeyOTP)
{
    return yubiKeyOTP.substr(0, 12);
}

std::string YubiKeyAuth::GetAuthURL()
{
    return AuthURL;
}
void YubiKeyAuth::SetAuthURL(std::string authURL)
{
    if(authURL.substr(0,7) == "http://")
    {
        authURL = authURL.substr(7);
    }
    else if(authURL.substr(0,8) == "https://")
    {
        authURL = authURL.substr(8);
    }
    AuthHostName = authURL.substr(0,
        (authURL.find_first_of('/') + 1)
    );
    AuthPath = authURL.substr(AuthHostName.length() + 1);
    AuthURL = authURL;
}

YubiKeyStatus YubiKeyAuth::AuthenticateOTP(std::string yubiKeyOTP)
{
    tcp::socket* authServSocket = SendAuthRequest(yubiKeyOTP);
    string responseData = GetAuthResponse(authServSocket);
    delete authServSocket;
    return GetStatusFromResponse(responseData);
}
boost::asio::ip::tcp::socket* YubiKeyAuth::SendAuthRequest(std::string yubiKeyOTP)
{
    boost::asio::io_service io_service;
    tcp::resolver resolver(io_service);
    tcp::resolver::query query(AuthHostName, "http");
    tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
    tcp::socket* socket = new tcp::socket(io_service);
    boost::asio::connect(*socket, endpoint_iterator);
    boost::asio::streambuf request;
    std::ostream requestStream(&request);
    string requestData = MakeRequestData(yubiKeyOTP);
    requestStream << requestData;
    boost::asio::write(*socket, request);
    return socket;
}
string YubiKeyAuth::MakeRequestData(string yubiKeyOTP)
{
    string requestData = "";
    requestData += "GET " + AuthPath;
    requestData += "?id=" + ClientAPIID;
    requestData += "&otp=" + yubiKeyOTP;
    requestData += "&nonce=" + MakeNonce() += " HTTP/1.1\r\n";
    requestData += "Host:" + AuthHostName + "\r\n";
    requestData += "Accept: */*\r\n";
    requestData += "Connection: keep-alive\r\n\r\n";
    return requestData;
}
string YubiKeyAuth::MakeNonce()
{
    string nonce = "";
    std::string chars(
        "abcdefghijklmnopqrstuvwxyz"
        "1234567890");
    boost::random::random_device rng;
    boost::random::uniform_int_distribution<> index_dist(0, chars.size() - 1);
    for(int i = 0; i < 40; ++i) {
        nonce += chars[index_dist(rng)];
    }
    return nonce;
}
string YubiKeyAuth::GetAuthResponse(tcp::socket* socket)
{
    string responseData = "";
    boost::asio::streambuf response;
    boost::asio::read_until(*socket, response, "\r\n");
    if(CheckResponse(response))
    {
        boost::asio::read_until(*socket, response, "\r\n\r\n");
        boost::asio::streambuf::const_buffers_type bufs = response.data();
        responseData = string(boost::asio::buffers_begin(bufs), boost::asio::buffers_begin(bufs) + response.size());
        return responseData;
    }
    else
    {
        return responseData;
    }
}
bool YubiKeyAuth::CheckResponse(boost::asio::streambuf &response)
{
    std::istream response_stream(&response);
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    if (!response_stream || http_version.substr(0, 5) != "HTTP/")
    {
        cout << "Invalid response from YubiKey authentication server." << endl;
        return false;
    }
    if (status_code != 200)
    {
        cout << "YubiKey authentication server returned with status code " << status_code << endl;
        return false;
    }
    else
    {
        return true;
    }
}
YubiKeyStatus YubiKeyAuth::GetStatusFromResponse(string responseData)
{
    istringstream strStream(responseData);
    string line = "";
    YubiKeyStatus status;
    bool statusFound = false;
    while(getline(strStream, line) && !statusFound)
    {
        if(boost::starts_with(line, "status="))   
        {
            statusFound = true;
            string statusText = line.substr(7);
            statusText.erase(std::remove(statusText.begin(), statusText.end(), '\r'), statusText.end());
            std::map<string,string>::iterator search = YKStatusList.find(statusText);
            if(search != YKStatusList.end())
            {
                status.Name = statusText;
                status.Meaning = YKStatusList[statusText];
            }
        }
    }
    return status;
}


void YubiKeyAuth::PrintYubiStatus(YubiKeyStatus status)
{
    cout << status.Name << ": " << status.Meaning << endl;
}


