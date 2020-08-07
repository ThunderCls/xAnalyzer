#pragma once

#include <string>
#include <sstream>
#include "../Plugin.h"

class StringUtils
{
public:
	static std::string ToHex(const duint value)
	{
		std::stringstream stream;
		stream << std::hex << value;
		return stream.str();
	}

	static duint ToInt(const std::string str)
	{
		duint value = 0;

		if (!str.empty())
		{
			std::istringstream iss(str);
			iss >> std::hex >> value;
		}

		return value;
	}
	
	static std::string FileFromPath(const std::string& path, bool removeExtension = false)
	{
		char fileName[_MAX_FNAME];
		char ext[_MAX_EXT];

		if(_splitpath_s(path.c_str(), nullptr, 0, nullptr, 0, fileName, _MAX_FNAME, ext, _MAX_EXT) == 0)
		{
			return removeExtension ? std::string(fileName) : std::string(fileName) + std::string(ext);
		}

		return "";
	}
};
