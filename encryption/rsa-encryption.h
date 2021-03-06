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

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

#include <rsa.h>

struct RSAKeyPair
{
    bool Loaded;
    bool Validated;
    CryptoPP::RSA::PrivateKey PrivateKey;
    CryptoPP::RSA::PublicKey PublicKey;
};

class Encryption
{
public:
    std::string RSAEncrypt(RSAKeyPair keyPair, std::string plainText);
    std::string RSADecrypt(RSAKeyPair keyPair, std::string cipherText);
    
    RSAKeyPair RSAGenerateKeys();
    
    bool SaveKeys(RSAKeyPair keyPair, 
                  std::string privateKeyFileName = "RSA-Private.key",
                  std::string publicKeyFileName = "RSA-Public.key");
    
    RSAKeyPair LoadKeys(std::string privateKeyFileName = "RSA-Private.key",
                        std::string publicKeyFileName = "RSA-Public.key");
    
private:
    bool SavePrivateKey(CryptoPP::RSA::PrivateKey key, std::string fileName);
    bool SavePublicKey(CryptoPP::RSA::PublicKey key, std::string fileName);
    
    RSAKeyPair LoadPrivateKey(RSAKeyPair keyPair, std::string fileName);
    RSAKeyPair LoadPublicKey(RSAKeyPair keyPair, std::string fileName);
    RSAKeyPair ValidateKeyPair(RSAKeyPair keyPair);
};

#endif // ENCRYPTION_H
