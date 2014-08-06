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

#include "sha3-hashing.h"

#include <string>
#include <osrng.h>
#include <sha3.h>
#include <hex.h>

using namespace std;

SHA3Hash SHA3Hashing::HashString(std::string plainText, std::string salt)
{
    if(salt.length() == 0)
    {
        salt = GetSalt();
    }
    string toHash = salt + plainText;
    CryptoPP::SHA3_512 hash;
    byte digest[ CryptoPP::SHA3_512::DIGESTSIZE ];
    hash.CalculateDigest( digest, (byte*) toHash.c_str(), toHash.length() );
    CryptoPP::HexEncoder encoder;
    std::string hashStr;
    encoder.Attach( new CryptoPP::StringSink( hashStr ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();
    SHA3Hash output;
    output.Hash = hashStr;
    output.Salt = salt;
    return output;
}

std::string SHA3Hashing::GetSalt()
{
    const unsigned int BLOCKSIZE = 1024;
    byte saltScratch[ BLOCKSIZE ];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock( saltScratch, BLOCKSIZE );
    string salt;
    CryptoPP::StringSource ss(saltScratch, sizeof(saltScratch), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(salt)
        )
    );
    return salt;
}
