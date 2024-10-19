#ifndef RTSP_H
#define RTSP_H

#include <string>
#include "Utils.h"
#include "Connector.h"
#include "FileUpdater.h"

struct lopaStr {
    char login[32];
    char pass[32];
    char other[32];
};

namespace RTSP {
    lopaStr RTSPBrute(const char *ip, int port);
    lopaStr RTSPLobby(const char *ip, int port);
}

#endif // RTSP_H
