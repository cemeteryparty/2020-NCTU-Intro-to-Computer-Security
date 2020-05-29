#include <iostream>
#include <fstream>

using namespace std;
int main(int argc,char const *argv[]){
	ifstream fin("crack_me.log");
	ofstream fout("task1_result.log");
	string s;
	fin >> s;
	string tmp = s;
	for(int si = 0;si < s.length();si++)
		s[si] ^= 229;
	fout << s;	
	return 0;
}
