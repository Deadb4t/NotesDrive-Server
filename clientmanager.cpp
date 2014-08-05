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

#include "clientmanager.h"

#include <iostream>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "authentication/yubikeyauth.h"
#include "encryption/rsa-encryption.h"
#include "encryption/utils-encryption.h"

using namespace std;

ClientManager::ClientManager()
{
    
}

ClientManager::~ClientManager()
{

}

void ClientManager::AddClient(boost::asio::ip::tcp::socket *clientSocket)
{
    Client newClient;
    cout << "Getting client details..." << endl;
    newClient.Socket = clientSocket;
    GetClientDetails(newClient);
    cout << "Authenticating client details..." << endl;
    AuthenticateClient(newClient);
    if(newClient.Authenticated)
    {
        SendAuthenticationResponse(newClient);
        cout << "Client authenticated." << endl;
        Clients.push_back(newClient);
    }
    else
    {
        SendAuthenticationResponse(newClient);
        cout << "Client authentication failed." << endl;
        newClient.Socket->close();
    }
}

void ClientManager::GetClientDetails(Client &newClient)
{
    cout << "Getting client user name..." << endl;
    GetClientUserName(newClient);
    cout << "Client username: " << newClient.UserName << endl;
    cout << "Getting client YubiKey OTP..." << endl;
    GetClientYubiKeyOTP(newClient);
    cout << "Client YubiKey OTP: " << newClient.YubiKeyOTP << endl;
}
void ClientManager::GetClientUserName(Client& newClient)
{
    char userNameChar[max_user_name_size];
    string userName = "";
    try
    {
        size_t userNameCharLen = boost::asio::read(*newClient.Socket,  boost::asio::buffer(userNameChar, max_user_name_size));
        userName = userNameChar;
    }
    catch(std::exception &e)
    {
        cout << "Error: Could not retrive clients username." << endl;
        cout << "Exeption: " << e.what() << endl;
    }
    newClient.UserName = userName;
}
void ClientManager::GetClientYubiKeyOTP(Client& newClient)
{
    char yubiKeyOTPChar[max_ykotp_size];
    string yubiKeyOTP = "";
    try
    {
        size_t YubiKeyLen = boost::asio::read(*newClient.Socket,  boost::asio::buffer(yubiKeyOTPChar, max_ykotp_size));
        yubiKeyOTP = yubiKeyOTPChar;
    }
    catch(std::exception &e)
    {
        cout << "Error: Could not retrive clients YubiKey OTP." << endl;
        cout << "Exeption: " << e.what() << endl;
    }
    newClient.YubiKeyOTP = yubiKeyOTP;
}

void ClientManager::AuthenticateClient(Client &newClient)
{
    if(newClient.UserName.length() == 0 || 
        newClient.YubiKeyOTP.length() == 0 || 
        YKAuth.VerifyOTP(newClient.YubiKeyOTP) == false)
    {
        newClient.Authenticated = false;
        return;
    }
    newClient.YubiKeyID = YKAuth.GetYubiKeyUID(newClient.YubiKeyOTP);
    if(AuthenticateYubiKey(newClient))
    {
        newClient.Authenticated = true;
        return;
    }
}
bool ClientManager::AuthenticateYubiKey(Client &newClient)
{
    if(YKAuth.VerifyOTP(newClient.YubiKeyOTP) == false)
    {
        cout << "Invalid OTP" << endl;
        return false;
    }
    YubiKeyStatus status = YKAuth.AuthenticateOTP(newClient.YubiKeyOTP);
    YKAuth.PrintYubiStatus(status);
    if(status.Name == "OK")
    {
        return true;
    }
    else
    {
        return false;
    }
}

void ClientManager::SendAuthenticationResponse(Client& newClient)
{
    cout << "Informing client of authentication status." << endl;
    try
    {
        size_t length = 32;
        string status = "-";
        if(newClient.Authenticated)
        {
            status = "+";
        }
        boost::asio::write(*newClient.Socket, boost::asio::buffer(status.c_str(), length));
    }
    catch(std::exception& e)
    {
        std::cerr << "Exception in sending authentication status: " << e.what() << "\n";
    }
}
