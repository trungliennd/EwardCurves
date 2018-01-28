#include <stdio.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>

using namespace std;

int main() {
    
	ofstream myfile("sumNumber.txt",ios::trunc);
	int i = 1000000;
	while(i > 0 ) {
		int rd = rand() % 10000 + 1;
		myfile << rd;
		myfile << " ";		
		i--;
	}
	
	myfile.close();
	printf("asdsa");    
    
}
