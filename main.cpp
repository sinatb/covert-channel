#include "covert.h"
#include <iostream>
#include "stdexcept"
using namespace std;
int main()  {

    string ip;
    cout << "enter ip address" << '\n';
    cin >> ip;
    try {
        covert_handler c(ip);
        c.start();
//        string message = "hello jksdhgkldsjahgajksdhlgjkadshljgldjasghjkljk";
//        c.add_message(message);
//        string message2 = "hoesin pishgahi";
//        c.add_message(message2);
        while(c.should_run()) {
        }
    }catch (const exception& e){
        cout <<"exception is : "<< e.what() << '\n';
    }
    return 0;
}