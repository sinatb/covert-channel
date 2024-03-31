#include "covert.h"
#include "stdexcept"
using namespace std;
int main()  {

    string ip;
    cout << "enter ip address" << '\n';
    cin >> ip;
    try {
        covert_handler c(ip);
        while (true){

        }
    }catch (const exception& e){
        cout <<"exception is : "<< e.what() << '\n';
    }
    return 0;
}