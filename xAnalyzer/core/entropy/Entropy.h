#include <string>

class Entropy
{
public:
	Entropy(std::string pFileName);
	double GetEntropy();
	double GetEntropyFromDisk(); // TODO: maybe implement ?
	bool IsHigh();

private:
	const double packedEntropyThreshold = 6.75;
	std::string fileName;

	//void GetPEFileData();
};
