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

#include <iostream>
#include <string>

#include "server.h"

using namespace std;

void ShowWelcomeMsg();

int main(int argc, char **argv) {
    ShowWelcomeMsg();
    Server s;
    return 0;
}

void ShowWelcomeMsg()
{
    cout << "  _   _       _            _____       _           " << endl;
    cout << " | \\ | |     | |          |  __ \\     (_)          " << endl;
    cout << " |  \\| | ___ | |_ ___  ___| |  | |_ __ ___   _____ " << endl;
    cout << " | . ` |/ _ \\| __/ _ \\/ __| |  | | '__| \\ \\ / / _ \\" << endl;
    cout << " | |\\  | (_) | ||  __/\\__ \\ |__| | |  | |\\ V /  __/" << endl;
    cout << " |_| \\_|\\___/ \\__\\___||___/_____/|_|  |_| \\_/ \\___|" << endl;
    cout << endl;
    cout << endl;
}

