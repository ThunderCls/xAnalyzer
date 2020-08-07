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

bool PEParser::CodeSection(duint& startAddress, duint& endAddress, bool rva)
{
	if (NtHeader != nullptr)
	{
		startAddress = NtHeader->OptionalHeader.BaseOfCode;
		endAddress = NtHeader->OptionalHeader.BaseOfCode + NtHeader->OptionalHeader.SizeOfCode;

		// align code section size with section alignment value
		if (endAddress < NtHeader->OptionalHeader.SectionAlignment)
		{
			endAddress = NtHeader->OptionalHeader.SectionAlignment;
		}
		if (endAddress % NtHeader->OptionalHeader.SectionAlignment > 0)
		{
			duint multiplier = endAddress / NtHeader->OptionalHeader.SectionAlignment;
			if (multiplier > 0)
			{
				endAddress = ++multiplier * NtHeader->OptionalHeader.SectionAlignment;
			}
		}
		
		if (rva)
		{
			startAddress += NtHeader->OptionalHeader.ImageBase;
			endAddress += NtHeader->OptionalHeader.ImageBase;
		}

		--endAddress;
		return true;
	}

	return false;
}

duint PEParser::EntryPoint(bool rva)
{
	return rva ? NtHeader->OptionalHeader.AddressOfEntryPoint + NtHeader->OptionalHeader.ImageBase :
				 NtHeader->OptionalHeader.AddressOfEntryPoint;
}

int PEParser::ExecutableSections()
{
	duint startCodeBase = 0;
	duint endCodeBase = 0;
	if(!CodeSection(startCodeBase, endCodeBase, false))
	{
		return -1;
	}

	// check if other sections have IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE set
	int additionalSections = 0;
	for (const auto section : Sections)
	{
		// exclude code section and sections with size equals zero
		if (section->Misc.VirtualSize == 0 ||
			section->VirtualAddress >= startCodeBase &&
			(section->VirtualAddress + section->Misc.VirtualSize) <= endCodeBase)
		{
			continue;
		}
		
		if(section->Characteristics & IMAGE_SCN_CNT_CODE || 
			section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			additionalSections++;
		}		
	}

	return additionalSections;
}
