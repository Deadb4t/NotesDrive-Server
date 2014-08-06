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

#ifndef SHA3HASHING_H
#define SHA3HASHING_H

#include <string>

struct SHA3Hash
{
    std::string Hash;
    std::string Salt;
};

class SHA3Hashing
{
    public:
        static SHA3Hash HashString(std::string plainText, std::string salt = "");
    private:
        static std::string GetSalt();
};

#endif // SHA3HASHING_H
