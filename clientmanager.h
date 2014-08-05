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

#ifndef CLIENTMGR_H
#define CLIENTMGR_H

#include <vector>
#include <string>

#include <boost/asio/ip/tcp.hpp>

#include "authentication/yubikeyauth.h"

struct Client
{
    boost::asio::ip::tcp::socket *Socket;
    bool Authenticated;
    std::string UserName;
    std::string YubiKeyOTP;
    std::string YubiKeyID;
    std::string Password;
};

class ClientManager
{
    
    enum {max_user_name_size = 128};
    enum {max_ykotp_size = 48};
    
    public:
        ClientManager();
        ~ClientManager();
        void AddClient(boost::asio::ip::tcp::socket *clientSocket);
        
   private:
       void AuthenticateClient(Client &newClient);
       void GetClientDetails(Client &newClient);
       void GetClientUserName(Client &newClient);
       void GetClientYubiKeyOTP(Client &newClient);
       bool AuthenticateYubiKey(Client &newClient);
       
       void SendAuthenticationResponse(Client &newClient);
       
       std::vector<Client> Clients;
       YubiKeyAuth YKAuth;
};

#endif // CLIENTMGR_H
