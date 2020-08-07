#ifndef UNIT_TEST
#define UNIT_TEST

#include "CppUnitTest.h"
#include "Windows.h"
#include "../xAnalyzer/core/utils/StringUtils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace Test_xAnalyzer
{		
	TEST_CLASS(UnitTest)
	{
	public:
		
		TEST_METHOD(TestFileFromPath)
		{
			std::string module = "executable.exe";
			Assert::AreEqual(std::string("executable"), StringUtils::FileFromPath(module, true));
		}

	};
}

#endif