#include "covert.h"
#include "stdexcept"
using namespace std;
int main()  {

    string ip;
    cout << "enter ip address" << '\n';
    cin >> ip;
    try {
        string message = "hello jksdhgkldsjahgajksdhlgjkadshljgldjasghjkljk";
        covert_handler c(ip);
        c.receive_message();
    }catch (const exception& e){
        cout <<"exception is : "<< e.what() << '\n';
    }
    return 0;
}