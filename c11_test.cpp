#include <iostream>
#include <vector>
#include <iterator>
#include <string>

#include "c11_test.h"

int std_test_container()
{
    std::vector<std::string> vs = {"this is a test","hello", "world!"};

    for(auto a:vs)
    {
        std::cout << a << " ";
    }
    std::cout << std::endl;

    vs.clear();

    for(int i=0;i<100;i++){
        std::string s = "this is a test string: " + std::to_string(i);
        vs.push_back(s);
    }

    for(auto a:vs)
    {
        std::cout << a << " " << std::endl;
    }
    std::cout << std::endl;

    
    return 0;
}