#include "ini.h"
#include <iostream>
#include <Windows.h> 

IniManager::IniManager(char* szFileName)
{
	ZeroMemory(m_szFileName, MAX_PATH);
	strcpy_s(m_szFileName, MAX_PATH, szFileName);
}

int IniManager::ReadInteger(char* szSection, char* szKey, int iDefaultValue)
{
	int iResult = GetPrivateProfileInt(szSection, szKey, iDefaultValue, m_szFileName);
	return iResult;
}

double IniManager::ReadDouble(char* szSection, char* szKey, float fltDefaultValue)
{
	char szResult[MAX_PATH] = "";
	char szDefault[MAX_PATH] = "";

	sprintf_s(szDefault, "%f", fltDefaultValue);
	GetPrivateProfileString(szSection, szKey, szDefault, szResult, MAX_PATH, m_szFileName);
	return atof(szResult);

}

bool IniManager::ReadBoolean(char* szSection, char* szKey, bool bolDefaultValue)
{
	char szResult[10];
	char szDefault[10];

	sprintf_s(szDefault, "%s", bolDefaultValue ? "true" : "false");
	GetPrivateProfileString(szSection, szKey, szDefault, szResult, 10, m_szFileName);

	return (strcmp(szResult, "true") == 0);
}

std::string IniManager::ReadString(char* szSection, char* szKey, const char* szDefaultValue)
{
	std::string szResult;
	GetPrivateProfileString((LPCSTR)szSection, (LPCSTR)szKey, (LPCSTR)szDefaultValue, (LPSTR)szResult.c_str(), 255, (LPCSTR)m_szFileName);
	return szResult;
}

void IniManager::WriteInteger(char* szSection, char* szKey, int iValue)
{
	char szValue[MAX_PATH] = "";
	sprintf_s(szValue, "%d", iValue);
	WritePrivateProfileString(szSection, szKey, szValue, m_szFileName);
}

void IniManager::WriteDouble(char* szSection, char* szKey, double fltValue)
{
	char szValue[MAX_PATH] = "";
	sprintf_s(szValue, "%lf", fltValue);
	WritePrivateProfileString(szSection, szKey, szValue, m_szFileName);
}

void IniManager::WriteBoolean(char* szSection, char* szKey, bool bolValue)
{
	char szValue[MAX_PATH] = "";
	sprintf_s(szValue, "%s", bolValue ? "true" : "false");
	WritePrivateProfileString(szSection, szKey, szValue, m_szFileName);
}

void IniManager::WriteString(char* szSection, char* szKey, char* szValue)
{
	WritePrivateProfileString(szSection, szKey, szValue, m_szFileName);
}