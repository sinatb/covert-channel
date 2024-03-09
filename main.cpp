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
        char *message = "hello jksdhgkldsjahgajksdhlgjkadshljgldjasghjkljk";
        c.send_covert_message(message);
    }catch (const exception& e){
        cout <<"exception is : "<< e.what() << '\n';
    }
    return 0;
}