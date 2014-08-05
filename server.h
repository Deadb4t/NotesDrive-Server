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

#ifndef SERVER_H
#define SERVER_H

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/thread.hpp>

#include "clientmanager.h"


class Server
{
    public:
        Server();
        ~Server();
        
    private:
        void LoadConfig();
        
        bool ConfigFileFound();
        
        void LoadConfigFile();
        void ApplyConifg(std::string ipStr, std::string portStr, 
                                 std::string usePasswordStr, std::string useYubiKeyStr);
        bool IsValidIP(std::string IPStr);
        bool IsValidPort(std::string portStr);
        bool IsValidBool(std::string boolStr);
        
        void MakeConfigFile();
        void SaveConifg(std::string ipStr, std::string portStr, 
                        std::string usePasswordStr, std::string useYubiKeyStr);
        void RemoveCurrentConifg();
        
        void StartListenerThread();
        void StartListener();
        void HandleAccept(boost::asio::ip::tcp::socket *newSocket);
        
        void StartCommandPrompt();
        
        bool ServerRunning;
        bool UsePassword;
        bool UseYubiKey;
        ClientManager *ClientMgr;
        boost::asio::ip::address ServerAddress;
        boost::asio::ip::tcp::endpoint Endpoint;
        boost::asio::io_service IOService;
        boost::asio::ip::tcp::acceptor *ListenAcceptor;
        boost::thread* ListenThread;
};

#endif // SERVER_H
