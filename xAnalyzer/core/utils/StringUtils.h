#pragma once

#include <string>
#include <sstream>
#include "../../pluginsdk/_plugin_types.h"

class StringUtils
{
public:
	static std::string ToHex(duint value)
	{
		std::stringstream stream;
		stream << std::hex << value;
		return stream.str();
	}
};
