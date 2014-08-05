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

#include "server.h"

#include <string>
#include <iostream>
#include <fstream>

#include <boost/system/error_code.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/filesystem.hpp>


using namespace boost::asio::ip;
using namespace std;

Server::Server()
{
    ServerRunning = true;
    LoadConfig();
    ClientMgr = new ClientManager();
    StartListenerThread();
    StartCommandPrompt();
}

Server::~Server()
{
    ListenAcceptor->cancel();
}

void Server::LoadConfig()
{
    if(ConfigFileFound())
    {
        LoadConfigFile();
    }
    else
    {
        MakeConfigFile();
    }
}
bool Server::ConfigFileFound()
{
    try
    {
        boost::filesystem::path configPath("notesdrive.config");
        if(boost::filesystem::exists(configPath) && boost::filesystem::is_regular_file(configPath))
        {
            cout << "Config found, loading..." << endl;
            return true;
        }
        else
        {
            cout << "Config not found, generating new one..." << endl;
            return false;
        }
    }
    catch(const boost::filesystem::filesystem_error &e)
    {
        cout << "Error loading config file: " << e.what() << endl;
        return false;
    }
}
void Server::LoadConfigFile()
{
    ifstream configFileStream;
    string line;
    if(configFileStream.is_open())
    {
        getline(configFileStream,line);
        string ipStr = line;
        getline(configFileStream,line);
        string portStr = line;
        getline(configFileStream,line);
        string usePasswordStr = line;
        getline(configFileStream,line);
        string useYubiKeyStr = line;
        ApplyConifg(ipStr, portStr, usePasswordStr, useYubiKeyStr);
    }
    
}
void Server::ApplyConifg(string ipStr, string portStr, 
                         string usePasswordStr, string useYubiKeyStr)
{
    if(IsValidIP(ipStr) && IsValidPort(portStr) &&
        IsValidBool(usePasswordStr) && IsValidBool(useYubiKeyStr))
    {
        int port = boost::lexical_cast<int>(portStr);
        ServerAddress = address::from_string(ipStr);
        Endpoint = tcp::endpoint(ServerAddress, port);
        UsePassword = boost::lexical_cast<bool>(usePasswordStr);
        UseYubiKey = boost::lexical_cast<bool>(useYubiKeyStr);
    }
    else
    {
        cout << "Config file is invalid, remaking config file..." << endl;
        MakeConfigFile();
    }
}
void Server::MakeConfigFile()
{
    cout << "--- Conifg Wizard ---" << endl;
    string ipStr;
    do
    {
        cout << "Enter IP address to use [0.0.0.0]: ";
        cin >> ipStr;
    } while(!IsValidIP(ipStr));
    string portStr;
    do
    {
        cout << "Enter port to use [8080]: ";
        cin >> portStr;
    } while(!IsValidPort(portStr));
    string usePasswordStr;
    do
    {
        cout << "Use passwords [1/0]: ";
        cin >> usePasswordStr;
    } while(!IsValidBool(usePasswordStr));
    string useYubiKeyStr;
    do
    {
        cout << "Use YubiKey one time passwords [1/0]: ";
        cin >> useYubiKeyStr;
    } while(!IsValidBool(useYubiKeyStr));
    ApplyConifg(ipStr, portStr, usePasswordStr, useYubiKeyStr);
    SaveConifg(ipStr, portStr, usePasswordStr, useYubiKeyStr);
}
void Server::SaveConifg(string ipStr, string portStr, 
                        string usePasswordStr, string useYubiKeyStr)
{
    boost::filesystem::path configPath("notesdrive.config");
    if(boost::filesystem::exists(configPath))
    {
        boost::filesystem::remove_all(configPath);
    }
    try
    {
        ofstream conifgFileStream;
        conifgFileStream.open("notesdrive.config");
        conifgFileStream << ipStr << endl << portStr << endl; 
        conifgFileStream << usePasswordStr << endl << useYubiKeyStr;
        conifgFileStream.close();
    }
    catch(std::exception &e)
    {
        cout << "Error writing config file: " << e.what() << endl;
    }
}

bool Server::IsValidIP(string IPStr)
{
    boost::system::error_code ec;
    boost::asio::ip::address::from_string( IPStr, ec );
    if(ec)
    {
        cout << "Invalid IP address, try again." << endl;
        return false;
    }
    else
    {
        return true;
    }
}
bool Server::IsValidPort(string portStr)
{
    try
    {
        int numberCheck = boost::lexical_cast<int>(portStr);
        if(numberCheck <= 60000 && numberCheck >= 1)
        {
            return true;
        }
        else
        {
            cout << "Port number invalid, port must be between 1 and 60000, try again." << endl;
        }
    }
    catch(boost::bad_lexical_cast& e)
    {
        cout << "Invalid port, try again." << endl;
        return false;
    }
}
bool Server::IsValidBool(string boolStr)
{
    try
    {
        boost::lexical_cast<bool>(boolStr);
        return true;
    }
    catch(boost::bad_lexical_cast &e)
    {
        cout << "Invalid boolian, try again." << endl;
        return false;
    }
}




void Server::StartListenerThread()
{
    cout << "Starting listen thread." << endl;
    ListenAcceptor = new tcp::acceptor(IOService, Endpoint);
    ListenThread = new boost::thread(&Server::StartListener, this);
    cout << "Listen thread started." << endl;
}
void Server::StartListener()
{
    tcp::socket *newSocket = new tcp::socket(IOService);
    ListenAcceptor->accept(*newSocket);
    boost::thread newClientThread(&Server::HandleAccept, this, newSocket);
    StartListener();
}
void Server::HandleAccept(tcp::socket* newSocket)
{
    cout << "Client connected." << endl;
    ClientMgr->AddClient(newSocket);
}

void Server::StartCommandPrompt()
{
    while(true)
    {
        boost::this_thread::sleep(boost::posix_time::milliseconds(10)); 
    }
}

