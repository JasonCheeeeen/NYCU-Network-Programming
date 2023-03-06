#include<iostream>
#include<vector>
#include<string>
#include<fstream>
#include<unordered_map>
#include<algorithm>
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>
#include<boost/asio.hpp>
#include<boost/bind/bind.hpp>
#include<boost/algorithm/string/split.hpp> // boost split
#include<boost/algorithm/string/replace.hpp> // replace_all
#include<boost/algorithm/string/classification.hpp> // is_any_of

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ip;

// declare global io_context !!
io_context io_context_;

class ServerBind : public enable_shared_from_this<ServerBind>{
public:
    ServerBind(shared_ptr<tcp::socket> socket, unsigned char* data, io_context& _io_context)
        : console_socket(socket), shell_socket(_io_context), shell_acceptor(_io_context){
            fill(console_data.begin(), console_data.end(), 0);
            fill(shell_data.begin(), shell_data.end(), 0);
        }

    void start(){
        do_bind();
    }

private:
    enum { max_length = 81920 };
    shared_ptr<tcp::socket> console_socket;
    tcp::socket shell_socket;
    tcp::acceptor shell_acceptor;
    unsigned char from_console_msg[8];
    unsigned char to_console_msg[8];
    array<char, max_length> console_data;
    array<char, max_length> shell_data;
    string shell_ip;
    string shell_port;
    unsigned short bind_port;

    void do_bind(){
        tcp::endpoint shell_endpoint(tcp::endpoint(tcp::v4(), 0));
        shell_acceptor.open(shell_endpoint.protocol());
        shell_acceptor.set_option(ip::tcp::acceptor::reuse_address(true));
        shell_acceptor.bind(shell_endpoint);
        shell_acceptor.listen();
        bind_port = shell_acceptor.local_endpoint().port();
        do_notify(); // notify console to ready to accept
    }

    void do_notify(){
        to_console_msg[0] = 0;
        to_console_msg[1] = 0x5a; // 90
        to_console_msg[2] = (unsigned char)(bind_port / 256);
        to_console_msg[3] = (unsigned char)(bind_port % 256);
        for(int i=4;i<8;i++){
            to_console_msg[i] = 0;
        }
        // send message back to console;
        auto self(shared_from_this());
        console_socket->async_send(buffer(to_console_msg, 8), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                // async accept shell connect to socks
                auto self(shared_from_this());
                shell_acceptor.async_accept(shell_socket, [this, self](boost::system::error_code _ec){
                    if(!_ec){
                        console_socket->async_send(buffer(to_console_msg, 8), [this, self](boost::system::error_code ec, size_t length){
                            if(!ec){
                                do_read(2);
                            }
                        });
                    }
                });
            }
        });    
    }

    void do_read(int opt){
        auto self(shared_from_this());
        if(opt == 0 || opt == 2){
            do_read_console();
        }
        if(opt == 1 || opt == 2){
            do_read_shell();
        }
    }

    void do_read_console(){
        auto self(shared_from_this());
        console_socket->async_read_some(buffer(console_data, max_length), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                do_write_shell(length);
            }
        });
    }

    void do_write_shell(size_t length){
        auto self(shared_from_this());
        shell_socket.async_send(buffer(console_data, length), [this, self, length](boost::system::error_code ec, size_t _length){
            if(!ec){
                if(length == _length){
                    do_read_console();
                }
                else{
                    do_write_shell(_length-length);
                }
            }
        });
    }

    void do_read_shell(){
        auto self(shared_from_this());
        shell_socket.async_read_some(buffer(shell_data, max_length), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                do_write_console(length);
            }
        });
    }

    void do_write_console(size_t length){
        auto self(shared_from_this());
        console_socket->async_send(buffer(shell_data, length), [this, self, length](boost::system::error_code ec, size_t _length){
            if(length == _length){
                do_read_shell();
            }
            else{
                do_write_console(_length-length);
            }
        });
    }
};


class ServerConnect : public enable_shared_from_this<ServerConnect>{
public:
    ServerConnect(shared_ptr<tcp::socket> socket, unsigned char* data, io_context& _io_context)
        : console_socket(socket), shell_socket(_io_context), shell_resolver(_io_context){
            fill(console_data.begin(), console_data.end(), 0);
            fill(shell_data.begin(), shell_data.end(), 0);
            getShellInfo(data);
        }

    void start(){
        do_resolve();
    }

private:
    enum { max_length = 4097 };
    shared_ptr<tcp::socket> console_socket;
    tcp::socket shell_socket;
    tcp::resolver shell_resolver;
    unsigned char from_console_msg[8];
    unsigned char to_console_msg[8];
    array<char, max_length> console_data;
    array<char, max_length> shell_data;
    string shell_ip;
    string shell_port;
    string http_host = "httpbin.org";

    void getShellInfo(unsigned char* data){
        for(int i=0;i<8;i++){
            from_console_msg[i] = data[i];
        }
        int port = ((int)data[2]*(0x100) + (int)data[3]);
        shell_port = to_string(port);
        shell_ip = to_string((int)data[4]) + "." + to_string((int)data[5]) + "." + to_string((int)data[6]) + "." + to_string((int)data[7]);
    }

    void do_resolve(){
        auto self(shared_from_this());
        tcp::resolver::query query(shell_ip, shell_port);
        shell_resolver.async_resolve(query, boost::bind(&ServerConnect::do_connect, self, boost::asio::placeholders::error, boost::asio::placeholders::iterator));
    }

    void do_connect(const boost::system::error_code &ec, tcp::resolver::iterator it){
        if(!ec){
            auto self(shared_from_this());
            tcp::endpoint shell_endpoint(address::from_string(shell_ip), stoi(shell_port));
            shell_socket.async_connect(shell_endpoint, boost::bind(&ServerConnect::do_connect_handler, self, boost::asio::placeholders::error));
        }
    }

    void do_connect_handler(const boost::system::error_code &ec){
        auto self(shared_from_this());
        if(!ec){
            to_console_msg[0] = 0x0;
            to_console_msg[1] = 0x5a;
            for(int i=2;i<8;i++){
                to_console_msg[i] = from_console_msg[i];
            }
            console_socket->async_send(buffer(to_console_msg, 8), [this, self](boost::system::error_code ec, size_t length){
                if(!ec){
                    do_read(2);
                }
            });
        }
    }

    void do_read(int opt){
        auto self(shared_from_this());
        if(opt == 0 || opt == 2){
            do_read_console();
        }
        if(opt == 1 || opt == 2){
            do_read_shell();
        }
    }

    void do_read_console(){
        auto self(shared_from_this());
        console_socket->async_read_some(buffer(console_data, max_length), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                do_write_shell(length);
            }
        });
    }

    void do_write_shell(size_t length){
        auto self(shared_from_this());
        shell_socket.async_send(buffer(console_data, length), [this, self](boost::system::error_code ec, size_t _length){
            if(!ec){
                do_read_console();
            }
        });
    }

    void do_read_shell(){
        auto self(shared_from_this());
        shell_socket.async_read_some(buffer(shell_data, max_length), [this, self](boost::system::error_code ec, std::size_t length){
            if(!ec){
                do_write_console(length);
            }
        });
    }

    void do_write_console(size_t length){
        auto self(shared_from_this());
        console_socket->async_send(buffer(shell_data, length), [this, self](boost::system::error_code ec, size_t _length){
            do_read_shell();
        });
    }
};

class CheckInfo : public enable_shared_from_this<CheckInfo>{
public:
    CheckInfo(tcp::socket socket)
        : socket_(move(socket)){}

    void start(){ 
        get_packet_info();
    }

private:
    tcp::socket socket_;
    enum { max_length = 1025 };
    unsigned char data_[max_length];

    void get_packet_info(){
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_, max_length),[this, self](boost::system::error_code ec, size_t length){
            if (!ec){
                unsigned char vn = data_[0];
                unsigned char cd = data_[1];

                bool legitimate = false;
                ifstream ifs("./socks.conf");
                string tmp;
                while(getline(ifs, tmp)){
                    // get firewall config
                    vector<string> info = {};
                    istringstream is(tmp);
                    string _tmp;
                    while(is >> _tmp){
                        info.push_back(_tmp);
                    }
                    // get destination address
                    vector<string> ip = {};
                    size_t start, end = 0;
                    start = info[2].find_first_not_of('.', end);
                    while(start != string::npos){
                        end = info[2].find_first_of('.', start);
                        ip.push_back(info[2].substr(start,end-start));
                        start = info[2].find_first_not_of('.', end);
                    }
                    if((cd == 1 && info[1] == "c") || (cd == 2 && info[1] == "b")){
                        // check the firewall info
                        if((data_[4] == (unsigned char)atoi(ip[0].c_str()) || ip[0] == "*") && (data_[5] == (unsigned char)atoi(ip[1].c_str()) || ip[1] == "*") && (data_[6] == (unsigned char)atoi(ip[2].c_str()) || ip[2] == "*") && (data_[7] == (unsigned char)atoi(ip[3].c_str()) || ip[3] == "*")){
                            legitimate = true;
                            break;
                        }
                    }
                }

                // print info of connect
                printInfo(cd, legitimate);

                // do function
                if(legitimate == 1){
                    shared_ptr<tcp::socket> socket_ptr = make_shared<ip::tcp::socket>(move(socket_));
                    if(cd == 1){
                        make_shared<ServerConnect>(socket_ptr, data_, io_context_)->start();
                    }
                    else{
                        make_shared<ServerBind>(socket_ptr, data_, io_context_)->start();
                    }
                }
                else{
                    // send reject message back to console.cgi
                    unsigned char reject_data[8];
                    reject_data[0] = 0;
                    reject_data[1] = 0x5b;
                    reject_data[2] = data_[2];
                    reject_data[3] = data_[3];
                    reject_data[4] = data_[4];
                    reject_data[5] = data_[5];
                    reject_data[6] = data_[6];
                    reject_data[7] = data_[7];
                    socket_.async_send(buffer(reject_data, 8),[self](boost::system::error_code ec, std::size_t length){
                        if(!ec){

                        }
                    });
                    get_packet_info();
                }
            }
        });
    }

    void printInfo(unsigned char _cd, bool _leg){
        cout<<"\n\033[1;34m========== Connect Message ==========\033[0m"<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"<S_IP>:    "<<socket_.remote_endpoint().address()<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"<S_PORT>:  "<<socket_.remote_endpoint().port()<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"<D_IP>:    "<<(int)data_[4]<<"."<<(int)data_[5]<<"."<<(int)data_[6]<<"."<<(int)data_[7]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"<D_PORT>:  "<<((int)data_[2]*(0x100)+(int)data_[3])<<endl;
        cout<<"\033[1;36m"<<"<Command>: ";
        if(_cd == 1){
            cout<<"CONNECT"<<"\033[0m"<<endl;
        }
        else{
            cout<<"BIND"<<"\033[0m"<<endl;
        }
        cout<<"\033[1;36m"<<"<Reply>:   ";
        if(_leg == true){
            cout<<"Accept"<<"\033[0m"<<endl;
        }
        else{
            cout<<"Reject"<<"\033[0m"<<endl;
        }
        cout<<"\033[1;34m=====================================\033[0m"<<endl;
    }
};

class server{
private:
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    void do_accept(){
        acceptor_.async_accept(socket_, [this](boost::system::error_code ec){
            if(!ec){
                io_context_.notify_fork(boost::asio::io_service::fork_prepare);
                pid_t _pid = fork();
                // child process
                if(_pid == 0){
                    io_context_.notify_fork(boost::asio::io_service::fork_child);
                    // close socks server to accept another client  
                    acceptor_.close();
                    make_shared<CheckInfo>(move(socket_))->start();
                }
                // parent process
                else{
                    io_context_.notify_fork(boost::asio::io_service::fork_parent);
                    socket_.close();
                }
            }
            do_accept();
        });
    }

public:
    server(short port)
    : acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)), socket_(io_context_){
        do_accept();
    }
};

int main(int argc, char* argv[]){

    if(argc != 2){
        cerr<<"Error: ./socks_server [port]"<<endl;
        exit(1);
    }
    int port = atoi(argv[1]);
    
    server s(port);
    // server s(io_context, port);
    io_context_.run();

    return 0;
}