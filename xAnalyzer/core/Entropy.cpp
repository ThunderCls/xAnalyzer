#include "Entropy.h"
#include "Plugin.h"
#include "PEParser.h"

/// <summary>
/// Constructor
/// </summary>
/// <param name="pFileName"></param>
Entropy::Entropy(std::string pFileName)
{
	fileName.assign(pFileName);
}

/// <summary>
/// Returns true if entropy is above the threshold
/// </summary>
/// <returns></returns>
/// Refs: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.120.9861&rep=rep1&type=pdf
bool Entropy::IsPacked()
{
	return (GetEntropy() > packedEntropyThreshold);
}

/// <summary>
/// Get entropy calculation from disk
/// </summary>
/// <returns></returns>
double Entropy::GetEntropyFromDisk()
{
	// NOTE: not implemented
	// https://github.com/hshantanu/Entropy-Calculator/blob/master/Source.cpp
	return 0;
}

/// <summary>
/// Calculate PEiD-like effective entropy for executables using the (Order-0) Shannon formula
/// </summary>
/// <returns></returns>
/// Refs: https://stackoverflow.com/questions/2789017/how-to-get-information-about-a-windows-executable-exe-using-c/2790424
/// Refs: https://reverseengineering.stackexchange.com/questions/9255/how-does-peid-calculate-entropy
///	Refs: https://github.com/hshantanu/Entropy-Calculator
double Entropy::GetEntropy()
{
	PEParser pe(this->fileName.c_str());
	if (!pe.ReadPEData())
	{
		return -1;
	}
	
	std::vector<double> entropies;
	for (const auto& section : pe.Sections)
	{	
		if (std::string(reinterpret_cast<char const*>(section->Name)) != ".rsrc")
		{
			long freq[UCHAR_MAX + 1] = { 0 };
			double entropy = 0;
			duint zeroBytes = 0;
			
			for (duint indexByte = 0; indexByte < section->SizeOfRawData; ++indexByte)
			{				
				BYTE byte = *(reinterpret_cast<BYTE*>(pe.GetMappedFile()) + section->PointerToRawData + indexByte);
				if (byte != 0x00)
				{
					freq[static_cast<int>(byte)]++;
				}
				else
				{
					zeroBytes++;
				}
			}

			duint effectiveSize = section->SizeOfRawData - zeroBytes;
			if (effectiveSize > 0)
			{
				for (int index = 1; index <= UCHAR_MAX; index++)
				{
					if (freq[index] != 0)
					{
						double frq = static_cast<double>(freq[index]) / effectiveSize;
						entropy += -frq * log2(frq);
					}
				}
				entropies.push_back(entropy);
			}
		}
	}

	// avg entropy
	double cummulativeEntropy = 0;
	for (auto entropy : entropies)
	{
		cummulativeEntropy += entropy;
	}

	// TODO: remove or show on gui
	//GuiAddLogMessage(std::string("Entropy = " + std::to_string(cummulativeEntropy / entropies.size())).c_str());
	return cummulativeEntropy / entropies.size();
}