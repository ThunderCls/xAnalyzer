#ifndef INI_H
#define INI_H

#include <string>       
#include <Windows.h>
using namespace std;

class IniManager
{
public:
	IniManager(string szFileName);

	int ReadInteger(char* szSection, char* szKey, int iDefaultValue);
	double ReadDouble(char* szSection, char* szKey, float fltDefaultValue);
	bool ReadBoolean(char* szSection, char* szKey, bool bolDefaultValue);
	string ReadString(char* szSection, char* szKey, const char* szDefaultValue);

	void WriteInteger(char* szSection, char* szKey, int iValue);
	void WriteDouble(char* szSection, char* szKey, double fltValue);
	void WriteBoolean(char* szSection, char* szKey, bool bolValue);
	void WriteString(char* szSection, char* szKey, char* szValue);
private:
	string m_szFileName;
};

#endif//INI_H