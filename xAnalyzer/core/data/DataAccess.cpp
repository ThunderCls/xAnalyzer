#include "DataAccess.h"

bool DataAccess::FindApiDefinition(const std::string moduleName, const std::string functName, ApiDefinition& apiDefinition, bool recursive)
{
	// TODO: implement	
	std::string functNameNoCharset = StripFunctionCharset(functName);

	
	return true;
}

std::string DataAccess::StripFunctionCharset(std::string functName)
{
	// Remove Stub suffix from function names if found
	auto stub = functName.find("Stub");
	if (stub != std::string::npos)
	{
		functName = functName.substr(0, stub);
	}
	// TODO: Until definition files with both A/W function versions are included
	// this has to be kept to force ASCII versions only
	// transform charsets search
	else if (functName.back() == 'A' || functName.back() == 'W')
	{
		functName.pop_back();
	}

	return functName;
}