#include<iostream>
#include<vector>
#include<string>
#include<unordered_map>
#include<algorithm>
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>
#include<boost/asio.hpp>
#include<boost/algorithm/string/split.hpp> // boost split
#include<boost/algorithm/string/classification.hpp> // is_any_of

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ip;

// declare global io_context !!
io_context io_context_;

class client : public enable_shared_from_this<client>{
public:
    client(tcp::socket socket)
        : socket_(move(socket)){}

    void start(){ 
        do_read();
    }

private:
    // environment structure
    unordered_map<string, string> required_env;

    tcp::socket socket_;
    enum { max_length = 1025 };
    char data_[max_length];
    pid_t _pid;

    void do_read(){
        auto self(shared_from_this());
        socket_.async_read_some(boost::asio::buffer(data_, max_length),[this, self](boost::system::error_code ec, size_t length){
                if (!ec){
                    Parse();
                    Exec();
                }
            }
        );
    }

    void Parse(){
        /*
            > GET / HTTP/1.1
            > Host: Jason:7777
            > User-Agent: curl/7.51.0
            > Accept: 
        */
        string _data = string(data_);
        // cout<<_data<<endl;
        // restore http request which has beeen splited
        vector<string> required_split;
        boost::split(required_split, _data, boost::is_any_of("\r\n "), boost::token_compress_on);
        
        for(vector<string>::iterator it=required_split.begin(); it!=required_split.end(); it++){
            int _index = it - required_split.begin();
            switch(_index){
                case 0:{
                    required_env["_REQUEST_METHOD"] = *it;
                    break;
                }
                case 1:{
                    required_env["_REQUEST_URL"] = *it;
                    size_t start = 0, end = 0;
                    start = required_env["_REQUEST_URL"].find_first_not_of('?', end);
                    end = required_env["_REQUEST_URL"].find_first_of('?', start);
                    if(end == string::npos){
                        required_env["_CGI"] = required_env["_REQUEST_URL"];
                    }
                    else{
                        required_env["_CGI"] = required_env["_REQUEST_URL"].substr(start, end-start);
                        required_env["_QUERY_STRING"] = required_env["_REQUEST_URL"].substr(end+1);
                    }  
                    break;
                }
                case 2:{
                    required_env["_SERVER_PROTOCOL"] = *it;
                    break;
                }
                case 4:{
                    required_env["_HTTP_HOST"] = *it;
                    break;
                }
                default:{
                    break;
                }
            }
            if(_index == 4){
                break;
            }
        }

        required_env["_SERVER_ADDR"] = socket_.local_endpoint().address().to_string();
        required_env["_REMOTE_ADDR"] = socket_.remote_endpoint().address().to_string();
        required_env["_SERVER_PORT"] = to_string(socket_.local_endpoint().port());
        required_env["_REMOTE_PORT"] = to_string(socket_.remote_endpoint().port());
    }

    void Exec(){
        /*
            1. fork
            2. set environment
            3. dup
            4. execvp
        */

        _pid = fork();
        if(_pid < 0){
            cerr<<"Error: fork() !\n";
            exit(1);
        }
        else if(_pid == 0){
            
            // set and check the environment
            cout<<"\n\033[1;34m========== Environment Setting ==========\033[0m"<<endl;

            setenv("REQUEST_METHOD", required_env["_REQUEST_METHOD"].c_str(), 1);
            setenv("REQUEST_URI", required_env["_REQUEST_URL"].c_str(), 1);
            setenv("QUERY_STRING", required_env["_QUERY_STRING"].c_str(), 1);
            setenv("SERVER_PROTOCOL", required_env["_SERVER_PROTOCOL"].c_str(), 1);
            setenv("HTTP_HOST", required_env["_HTTP_HOST"].c_str(), 1);
            setenv("SERVER_ADDR", required_env["_SERVER_ADDR"].c_str(), 1);
            setenv("SERVER_PORT", required_env["_SERVER_PORT"].c_str(), 1);
            setenv("REMOTE_ADDR", required_env["_REMOTE_ADDR"].c_str(), 1);
            setenv("REMOTE_PORT", required_env["_REMOTE_PORT"].c_str(), 1);

            cout<<"\033[1;36m"<<"REQUEST_METHOD:  "<<required_env["_REQUEST_METHOD"]<<"\033[0m"<<endl;
            cout<<"\033[1;36m"<<"REQUEST_URI:     "<<required_env["_REQUEST_URL"]<<"\033[0m"<<endl;
            cout<<"\033[1;36m"<<"QUERY_STRING:    "<<required_env["_QUERY_STRING"]<<"\033[0m"<<endl;
            cout<<"\033[1;36m"<<"SERVER_PROTOCOL: "<<required_env["_SERVER_PROTOCOL"]<<"\033[0m"<<endl;
            cout<<"\033[1;36m"<<"HTTP_HOST:       "<<required_env["_HTTP_HOST"]<<"\033[0m"<<endl;
            cout<<"\033[1;36m"<<"SERVER_ADDR:     "<<required_env["_SERVER_ADDR"]<<"\033[0m"<<endl;
            cout<<"\033[1;36m"<<"SERVER_PORT:     "<<required_env["_SERVER_PORT"]<<"\033[0m"<<endl;
            cout<<"\033[1;36m"<<"REMOTE_ADDR:     "<<required_env["_REMOTE_ADDR"]<<"\033[0m"<<endl;
            cout<<"\033[1;36m"<<"REMOTE_PORT:     "<<required_env["_REMOTE_PORT"]<<"\033[0m"<<endl;

            cout<<"\033[1;34m=========================================\033[0m"<<endl;

            // make execvp args
            string cgi_path = "." + required_env["_CGI"];
            char* cgi_pointer = new char(cgi_path.size()+1);
            strcpy(cgi_pointer, cgi_path.c_str());
            char* args[2] = {cgi_pointer, NULL};

            // dup
            dup2(socket_.native_handle(), STDIN_FILENO);
            dup2(socket_.native_handle(), STDOUT_FILENO);
            dup2(socket_.native_handle(), STDERR_FILENO);
            close(socket_.native_handle());

            // http need to return below two lines
            cout<<"HTTP/1.1 200 OK\r"<<endl;
            cout<<"Content-Type: text/html\r"<<endl;

            //exec -> cgi
            if(execvp(args[0], args) < 0){
                cerr<<"Error: execvp chi fail !\n";
                exit(1);
            }
        }
        else{
            int status;
            waitpid(_pid, &status, 0);
            socket_.close();
        }
    }
};

class server{
private:
    tcp::acceptor acceptor_;
    void do_accept(){
        acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket){
            if(!ec){
                make_shared<client>(move(socket))->start();
            }
            do_accept();
        });
    }

public:
    server(short port)
    : acceptor_(io_context_, tcp::endpoint(tcp::v4(), port)){
        do_accept();
    }
};

int main(int argc, char* argv[]){

    if(argc != 2){
        cerr<<"Error: ./http_server [port]"<<endl;
        exit(1);
    }
    int port = atoi(argv[1]);

    //io_context io_context;

    // prevent zombie process
    // signal(SIGCHLD, SIG_IGN);
    
    server s(port);
    // server s(io_context, port);
    io_context_.run();

    return 0;
}