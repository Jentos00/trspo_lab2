#pragma once
#ifndef PCH_H
#define PCH_H

#include "framework.h"
#include <stdio.h>
#include <iostream>
#include <windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <sstream>
#include <string>
#include <detours.h>

#endif
extern "C" void Hook_x64();
int HideFile(std::string& fileName);