#ifndef INI_H
#define INI_H

#include <string>       
#include <Windows.h>

class IniManager
{
public:
	IniManager(char* szFileName);

	int ReadInteger(char* szSection, char* szKey, int iDefaultValue);
	double ReadDouble(char* szSection, char* szKey, float fltDefaultValue);
	bool ReadBoolean(char* szSection, char* szKey, bool bolDefaultValue);
	std::string ReadString(char* szSection, char* szKey, const char* szDefaultValue);

	void WriteInteger(char* szSection, char* szKey, int iValue);
	void WriteDouble(char* szSection, char* szKey, double fltValue);
	void WriteBoolean(char* szSection, char* szKey, bool bolValue);
	void WriteString(char* szSection, char* szKey, char* szValue);
private:
	char m_szFileName[MAX_PATH];
};

#endif//INI_H