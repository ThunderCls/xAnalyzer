#include <string>
#include <unordered_map>
#include "ApiDefinition.h"

class DataAccess
{
public:
	DataAccess() = default;
	~DataAccess() = default;

	bool FindApiDefinition(const std::string moduleName, const std::string functName, ApiDefinition& apiDefinition, bool recursive);
private:
	std::string StripFunctionCharset(std::string functName);
};
