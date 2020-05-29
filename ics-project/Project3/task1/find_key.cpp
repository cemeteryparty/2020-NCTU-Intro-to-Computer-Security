#include <iostream>
#include <fstream>

using namespace std;
int main(int argc,char const *argv[]){
	//ifstream fin("/home/victim/Public/.Simple_Worm/crack_me.log");
	ifstream fin("task1_result.log");
	string s;
	fin >> s;
	for(int i = 0;i < 256;i++){
		string tmp = s;
		for(int si = 0;si < tmp.length();si++)
			tmp[si] ^= i;
		printf("key = %d: %s\n",i,tmp.c_str());	
	}
	return 0;
}
