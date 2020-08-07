#pragma once

#include <string>
#include <vector>

class ApiDefinition
{
public:
	typedef struct
	{
		std::string type;
		std::string name;
		bool isFlag;
		bool isPtr;
	}DefParameter;
	
	ApiDefinition() = default;
	~ApiDefinition() = default;

	std::string dllName;
	std::string functionName;
	std::vector<std::string> headers;
	std::vector<DefParameter> parameters;
private:

};
