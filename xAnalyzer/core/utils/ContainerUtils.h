#pragma once
#include <strstream>
#include <stack>

class ContainerUtils{
public:
	template<typename Type>
	static void FreeStack(std::stack<Type> &q)
	{
		std::stack<Type> empty;
		while (!q.empty())
		{
			delete q.top();
			q.pop();
		}
		std::swap(q, empty);
	}
};
