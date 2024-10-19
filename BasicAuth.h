#pragma once
#ifndef BASICAUTH_H
#define BASICAUTH_H

#include "Utils.h"
#include "Connector.h"
#include "externData.h"
#include "mainResources.h"
#include <string>

class BA {
private:
    static lopaStr BABrute(const char *ip, int port, bool performDoubleCheck);

public:
    static int checkOutput(const std::string& buffer, const char *ip, int port);
    static lopaStr BALobby(const std::string& ip, int port, bool performDoubleCheck);
};

#endif // BASICAUTH_H
