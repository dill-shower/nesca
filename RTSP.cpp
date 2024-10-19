#include "RTSP.h"

int checkOutput(const std::string *buffer, const char *ip, int port) {
    if (Utils::ustrstr(buffer, "not found") != -1) {
        return -1;
    }
    else if (Utils::ustrstr(buffer, "200 OK") != -1) {
        return 1;
    }

    return 0;
}

lopaStr RTSP::RTSPBrute(const char *ip, int port) {
    lopaStr lps = {"UNKNOWN", "", "[RTSP]"};
    std::string lpString;
    int passCounter = 0;
    int rowIndex = -1;
    int timeoutCounter = 0;
    std::string buffer;

    bool isDigest = true;
    std::string buff;
    Connector con;
    int res = con.checkIsDigestRTSP(ip, &buff);

    if (res == 2) {
        lps = {"", "", ""};
        rowIndex = Utils::addBARow(QString(ip), "Empty", "OK", rowIndex);
        return lps;
    }
    else if (res == -1) {
        rowIndex = Utils::addBARow(QString(ip), "--", "404", rowIndex);
        strcpy(lps.other, "404");
        return lps;
    }
    else if (res == 1) {
        isDigest = true;
    }
    else if (res == 0) {
        isDigest = false;
    }

    char login[32] = {0};
    char pass[32] = {0};
    for (int i = 0; i < MaxLogin; ++i) {
        FileUpdater::cv.wait(FileUpdater::lk, [] {return FileUpdater::ready; });
        strcpy(login, loginLst[i]);
        for (int j = 0; j < MaxPass; ++j) {
            FileUpdater::cv.wait(FileUpdater::lk, [] {return FileUpdater::ready; });
            if (!globalScanFlag) return lps;
            strcpy(pass, passLst[j]);

            lpString = std::string(login) + ":" + std::string(pass);

            res = con.nConnect(ip, port, &buffer, NULL, NULL, &lpString, false, true, isDigest);

            if (res != -1) {
                res = checkOutput(&buffer, ip, port);
                if (res == -1) {
                    rowIndex = Utils::addBARow(QString(ip), QString(login) + ":" + QString(pass), "404", rowIndex);
                    return lps;
                } else if (res == 1) {
                    rowIndex = Utils::addBARow(QString(ip), QString(login) + ":" + QString(pass), "OK", rowIndex);
                    strcpy(lps.login, login);
                    strcpy(lps.pass, pass);
                    return lps;
                }
            }
            else {
                if (++timeoutCounter > 3) {
                    rowIndex = Utils::addBARow(QString(ip), QString(login) + ":" + QString(pass), "TIMEOUT", rowIndex);
                    return lps;
                }
            }

            rowIndex = Utils::addBARow(QString(ip), QString(login) + ":" + QString(pass),
                                       QString::number((passCounter / static_cast<double>(MaxPass * MaxLogin)) * 100).mid(0, 4) + "%",
                                       rowIndex);

            ++passCounter;
            Sleep(50);
        }
    }

    rowIndex = Utils::addBARow(QString(ip), "--", "FAIL", rowIndex);
    return lps;
}

lopaStr RTSP::RTSPLobby(const char *ip, int port) {
    if (gMaxBrutingThreads > 0) {
        while (BrutingThrds >= gMaxBrutingThreads) Sleep(1000);

        ++baCount;
        ++BrutingThrds;
        stt->doEmitionUpdateArc(gTargets);
        const lopaStr &lps = RTSPBrute(ip, port);
        --BrutingThrds;

        return lps;
    }
    else {
        lopaStr lps = {"UNKNOWN", "", ""};
        return lps;
    }
}
