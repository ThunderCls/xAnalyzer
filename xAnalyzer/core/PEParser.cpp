#include "PEParser.h"

PEParser::PEParser(){};

PEParser::PEParser(const char* filePath)
{
	fileName.assign(filePath);
	hFile = INVALID_HANDLE_VALUE;
	hMap = nullptr;
	mFile = nullptr;
}

PEParser::~PEParser()
{
	FreeResources();
}

void PEParser::FreeResources()
{
	Sections.clear();
	if (mFile != nullptr)
	{
		UnmapViewOfFile(mFile);
		mFile = nullptr;
	}

	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = nullptr;
	}

	if (hMap != nullptr)
	{
		CloseHandle(hMap);
		hMap = nullptr;
	}
}


bool PEParser::ReadPEData()
{
	FreeResources();
	
	hFile = CreateFileA(fileName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	duint fileSize = GetFileSize(hFile, nullptr);

	hMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, fileSize, nullptr);
	if (hMap == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return false;
	}

	mFile = static_cast<char*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, fileSize));
	if (mFile == nullptr)
	{
		CloseHandle(hFile);
		CloseHandle(hMap);
		UnmapViewOfFile(mFile);
		return false;
	}

	DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(mFile);
	if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<duint>(mFile)+DosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSecHeader = {};
		pSecHeader = IMAGE_FIRST_SECTION(NtHeader);
		for (int sectionIndex = 0; sectionIndex < NtHeader->FileHeader.NumberOfSections; sectionIndex++)
		{
			Sections.push_back(pSecHeader);
			pSecHeader++;
		}

		return true;
	}

	return false;
}

bool PEParser::FindCodeSectionRange(duint& startAddress, duint& endAddress)
{
	if (NtHeader != nullptr)
	{
		startAddress = NtHeader->OptionalHeader.BaseOfCode + NtHeader->OptionalHeader.ImageBase;
		endAddress = NtHeader->OptionalHeader.BaseOfCode + NtHeader->OptionalHeader.SizeOfCode + NtHeader->OptionalHeader.ImageBase;
		return true;
	}

	return false;
}
