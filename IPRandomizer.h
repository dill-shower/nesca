#pragma once
#ifndef RAND_H
#define RAND_H

#include <vector>
#include <deque>
#include <algorithm>
#include <random>

struct IPRangeHolder {
    unsigned int ip1;
    unsigned int ip2;
};

class IPRandomizer
{
private:
    std::vector<IPRangeHolder> ipRangeVec;
    std::deque<unsigned int> shuffledRange;
    std::vector<unsigned int> shuffleOffset;
    int shuffleGap = 20000;
    int currentRangeIndex = 0;

private:
    void shuffleRange();

public:
    IPRandomizer(std::vector<IPRangeHolder> ipRangeVec, int shuffleGap = 20000);
    IPRandomizer(std::vector<IPRangeHolder> ipRangeVec);
    ~IPRandomizer();

    unsigned int getNext();
};

#endif
