#include "covert.h"
#include "stdexcept"
using namespace std;
int main()  {

    string cmd;
    cout << "Enter IP Address" << '\n';
    cin >> cmd;
    try {
        covert_handler c(cmd);
        while (cmd != "exit"){
            cout << "enter command" << '\n';
            getline(cin,cmd);
            if (cmd == "stats"){
                covert_handler::print_stats();
            }else if (cmd == "data"){
                covert_handler::print_data();
            }else if (cmd.find("send") != string::npos){
                c.send_message(cmd.substr(5).c_str());
            }
        }
    }catch (const exception& e){
        cout <<"exception is : "<< e.what() << '\n';
    }
    return 0;
}