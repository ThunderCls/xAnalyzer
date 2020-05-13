#pragma once

#include <windows.h>
#include <vector>
#include "../pluginsdk/_plugin_types.h"

class PEParser
{
public:
	PIMAGE_DOS_HEADER DosHeader = {};
	PIMAGE_NT_HEADERS NtHeader = {};
	std::vector<PIMAGE_SECTION_HEADER> Sections;

	PEParser();
	PEParser(const char* filePath);
	~PEParser();

	bool ReadPEData();
	bool FindCodeSectionRange(duint& startAddress, duint& endAddress);
	
	void SetFile(const char* filePath)
	{
		fileName.assign(filePath);
	};
	LPVOID GetMappedFile()
	{
		return mFile;
	}	
	
private:
	std::string fileName;
	HANDLE hFile;
	HANDLE hMap;
	char* mFile;

	void FreeResources();
};
