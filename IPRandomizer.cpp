#include "IPRandomizer.h"

IPRandomizer::IPRandomizer(std::vector<IPRangeHolder> ipRangeVec, int shuffleGap)
{
    this->ipRangeVec = ipRangeVec;
    this->shuffleGap = shuffleGap;

    for (int i = 0; i < ipRangeVec.size(); ++i) {
        this->shuffleOffset.push_back(0);
    }
}

IPRandomizer::IPRandomizer(std::vector<IPRangeHolder> ipRangeVec) : IPRandomizer(ipRangeVec, 20000) {}

IPRandomizer::~IPRandomizer()
{
    this->ipRangeVec.clear();
    this->shuffleOffset.clear();
}

void IPRandomizer::shuffleRange() {
    std::random_device rd;
    std::mt19937 rng(rd());

    for (int i = 0; i < this->ipRangeVec.size(); ++i) {
        IPRangeHolder ipRangeHolder = this->ipRangeVec[i];
        if (ipRangeHolder.ip1 + this->shuffleOffset[i] >= ipRangeHolder.ip2) {
            continue;
        }

        unsigned int rangeSize = ipRangeHolder.ip2 - (ipRangeHolder.ip1 + this->shuffleOffset[i] - 1);
        int offset = (rangeSize < this->shuffleGap ? rangeSize : this->shuffleGap);

        for (unsigned int j = this->shuffleOffset[i]; j < this->shuffleOffset[i] + offset; ++j) {
            this->shuffledRange.push_back(ipRangeHolder.ip1 + j);
        }

        this->shuffleOffset[i] += offset;
    }
    std::shuffle(this->shuffledRange.begin(), this->shuffledRange.end(), rng);
}

unsigned int IPRandomizer::getNext() {
    if (this->shuffledRange.empty()) {
        IPRangeHolder ipRangeHolder = this->ipRangeVec[this->currentRangeIndex];
        if (ipRangeHolder.ip1 + this->shuffleOffset[this->currentRangeIndex] >= ipRangeHolder.ip2) {
            this->currentRangeIndex++;
            if (this->currentRangeIndex >= this->ipRangeVec.size()) {
                this->currentRangeIndex = 0;
                std::fill(this->shuffleOffset.begin(), this->shuffleOffset.end(), 0);
            }
            ipRangeHolder = this->ipRangeVec[this->currentRangeIndex];
        }

        unsigned int rangeSize = ipRangeHolder.ip2 - (ipRangeHolder.ip1 + this->shuffleOffset[this->currentRangeIndex] - 1);
        int offset = (rangeSize < this->shuffleGap ? rangeSize : this->shuffleGap);

        for (unsigned int j = this->shuffleOffset[this->currentRangeIndex]; j < this->shuffleOffset[this->currentRangeIndex] + offset; ++j) {
            this->shuffledRange.push_back(ipRangeHolder.ip1 + j);
        }

        this->shuffleOffset[this->currentRangeIndex] += offset;
        std::random_device rd;
        std::mt19937 rng(rd());
        std::shuffle(this->shuffledRange.begin(), this->shuffledRange.end(), rng);
    }

    unsigned int ip = this->shuffledRange.front();
    this->shuffledRange.pop_front();
    return ip;
}
