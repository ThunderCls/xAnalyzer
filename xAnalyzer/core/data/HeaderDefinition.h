#include <string>
#include <unordered_map>
#include "../Plugin.h"

typedef enum
{
	None = 0,
	Flag,
	Enum
}ConstantType;

class HeaderDefinition
{
public:
	std::string name;
	std::string display;
	std::string base;
	ConstantType cType;
	std::unordered_map<std::string, duint> values;
private:
};
