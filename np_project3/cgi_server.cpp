#include<iostream>
#include<fstream>
#include<vector>
#include<string>
#include<map>
#include<unordered_map>
#include<algorithm>
#include<stdio.h>
#include<unistd.h>
#include<boost/asio.hpp>
#include<boost/algorithm/string/split.hpp> // boost split
#include<boost/algorithm/string/replace.hpp> // replace_all
#include<boost/algorithm/string/classification.hpp> // is_any_of

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ip;
// typedef shared_ptr<tcp::socket> global_socket;

// declare global io_context !!
io_context io_context_;
// global variable
struct serverInfo{
    string id;
    string host_name;
    string host_port;
    string file_name;
    serverInfo(){
        id = "";
        host_name = "";
        host_port = "";
        file_name = "";
    }
};
map<int, struct serverInfo> rsInfo;

class Shellsession : public enable_shared_from_this<Shellsession>{
public:
    Shellsession(shared_ptr<tcp::socket> ptr, tcp::resolver::query query, string id, string filename)
        : google_socket(ptr), _query(move(query)), _id(id), _file(filename){
            get_total_cmd();
        }

    void start(){
        do_resolve_connect(); // get socket's information;
    }
private:
    int cmd_count = 0;
    tcp::resolver _resolver{io_context_};
    tcp::socket shell_socket{io_context_};
    //tcp::socket google_socket;
    shared_ptr<tcp::socket> google_socket;
    tcp::resolver::query _query;
    string _id;
    string _file;
    enum { max_length = 10240 };
    char data_[max_length];
    vector<string> cmds = {};
    boost::system::error_code error;

    void escape(string &in){
        boost::replace_all(in, "&", "&amp;");
        boost::replace_all(in, "\"", "&quot;");
        boost::replace_all(in, "\'", "&apos;");
        boost::replace_all(in, "<", "&lt;");
        boost::replace_all(in, ">", "&gt;");
        boost::replace_all(in, "\r\n", "\n");
        boost::replace_all(in, "\n", "&NewLine;");
    }

    void output_shell(string ddata){
        auto self(shared_from_this());
        escape(ddata);
        string output_data = "";
        output_data += "<script>document.getElementById('s" + _id + "')";
        output_data += ".innerHTML += '" + ddata + "';</script>";
        //cout<<output_data<<endl;
        google_socket->async_write_some(buffer(output_data.c_str(), output_data.length()), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                //cout<<"output shell success !!!"<<endl;
                // do nothing...
            }
        });
    }

    void output_command(string ddata){
        auto self(shared_from_this());
        escape(ddata);
        string output_data = "";
        output_data += "<script>document.getElementById('s" + _id + "')";
        output_data += ".innerHTML += '<b>" + ddata + "</b>';</script>";
        //cout<<output_data<<endl;
        google_socket->async_write_some(buffer(output_data.c_str(), output_data.length()), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                //cout<<"output shell success !!!"<<endl;
                // do nothing...
            }
        });
    }

    void do_read(){
        /*
            bug: it need to clear the input buffer, if not, it will
            cause error and diffcult to debug, like me ...
        */
        memset(data_, '\0', max_length);
        auto self(shared_from_this());
        shell_socket.async_read_some(boost::asio::buffer(data_, max_length), [this, self](boost::system::error_code ec, size_t length){
                if(!ec){
                    string _data(data_);
                    output_shell(_data); // output from remote shell
                    if(find(_data.begin(), _data.end(), '%') != _data.end()){
                        string write_command = "";
                        write_command = cmds[cmd_count++];
                        output_command(write_command);
                        shell_socket.write_some(buffer(write_command));
                    }
                    do_read();
                }
            }
        );
    }

    void do_resolve_connect(){
        auto self(shared_from_this());
        // do resolve
        _resolver.async_resolve(_query, [this, self](boost::system::error_code ec, tcp::resolver::iterator it){
                if(!ec){
                    //do connect;
                    shell_socket.async_connect(*it, [this, self](boost::system::error_code ec){
                            if(!ec){
                                // connect finish and read from socket
                                do_read();
                            }
                        }
                    );
                }
            }
        );
    }

    void get_total_cmd(){
        ifstream ifs(_file);
        string in;
        while(getline(ifs,in)){
            in += "\n";
            cmds.push_back(in);
        }
        ifs.close();
    }
};

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
            
        // check the html request's input
        cout<<"\n\033[1;34m===========    HTML REQUEST   ===========\033[0m\n"<<endl;
        cout<<"\033[1;36m"<<"REQUEST_METHOD:  "<<required_env["_REQUEST_METHOD"]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"REQUEST_URL:     "<<required_env["_REQUEST_URL"]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"QUERY_STRING:    "<<required_env["_QUERY_STRING"]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"SERVER_PROTOCOL: "<<required_env["_SERVER_PROTOCOL"]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"HTTP_HOST:       "<<required_env["_HTTP_HOST"]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"SERVER_ADDR:     "<<required_env["_SERVER_ADDR"]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"SERVER_PORT:     "<<required_env["_SERVER_PORT"]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"REMOTE_ADDR:     "<<required_env["_REMOTE_ADDR"]<<"\033[0m"<<endl;
        cout<<"\033[1;36m"<<"REMOTE_PORT:     "<<required_env["_REMOTE_PORT"]<<"\033[0m\n"<<endl;
        cout<<"\033[1;34m=========================================\033[0m\n"<<endl;

        // check the CGI
        if(required_env["_CGI"] == "/console.cgi"){
            cout<<"\033[1;35mCurrent running console.cgi !!!\033[0m\n"<<endl;
            cout<<"\033[1;34m=========================================\033[0m\n"<<endl;
            do_console();
        }
        else{
            cout<<"\033[1;35mCurrent running panel.cgi !!!\033[0m\n"<<endl;
            cout<<"\033[1;34m=========================================\033[0m\n"<<endl;
            do_panel();
        }
    }

    void do_panel(){
        getPanelHeaderOutput();
    }

    void do_console(){
        // parse the query string
        getRemoteServerInfo();
        // header output
        getHeaderOutput();
        // connect to remote server for doing shell
        doShellSession();
    }

    void getPanelHeaderOutput(){
        auto self(shared_from_this());
        string header = "";
        header += 
        "HTTP/1.1 200 OK\r\n"
        "Content-type: text/html\r\n\r\n"
        "<!DOCTYPE html>"
        "<html lang=\"en\">"
        "  <head>"
        "    <title>NP Project 3 Panel</title>"
        "    <link"
        "      rel=\"stylesheet\""
        "      href=\"https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css\""
        "      integrity=\"sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2\""
        "      crossorigin=\"anonymous\""
        "    />"
        "    <link"
        "      href=\"https://fonts.googleapis.com/css?family=Source+Code+Pro\""
        "      rel=\"stylesheet\""
        "    />"
        "    <link"
        "      rel=\"icon\""
        "      type=\"image/png\""
        "      href=\"https://cdn4.iconfinder.com/data/icons/iconsimple-setting-time/512/dashboard-512.png\""
        "    />"
        "    <style>"
        "      * {"
        "        font-family: 'Source Code Pro', monospace;"
        "      }"
        "    </style>"
        "  </head>"
        "  <body class=\"bg-secondary pt-5\">";
        header += "    <form action=\"console.cgi\" method=\"GET\">";
        header += 
        "      <table class=\"table mx-auto bg-light\" style=\"width: inherit\">"
        "        <thead class=\"thead-dark\">"
        "          <tr>"
        "            <th scope=\"col\">#</th>"
        "            <th scope=\"col\">Host</th>"
        "            <th scope=\"col\">Port</th>"
        "            <th scope=\"col\">Input File</th>"
        "          </tr>"
        "        </thead>"
        "        <tbody>";
        for(int i=0; i<5; i++){
            header += 
            "          <tr>"
            "            <th scope=\"row\" class=\"align-middle\">Session ";
            header += to_string(i+1);
            header += "</th>";
            header +=
            "            <td>"
            "              <div class=\"input-group\">"
            "                <select name=\"h";
            header += to_string(i);
            header += "\" class=\"custom-select\">";
            header +=
            "                  <option></option>"
            "                  <option value=\"nplinux1.cs.nctu.edu.tw\">nplinux1</option>"
            "                  <option value=\"nplinux2.cs.nctu.edu.tw\">nplinux2</option>"
            "                  <option value=\"nplinux3.cs.nctu.edu.tw\">nplinux3</option>"
            "                  <option value=\"nplinux4.cs.nctu.edu.tw\">nplinux4</option>"
            "                  <option value=\"nplinux5.cs.nctu.edu.tw\">nplinux5</option>"
            "                  <option value=\"nplinux6.cs.nctu.edu.tw\">nplinux6</option>"
            "                  <option value=\"nplinux7.cs.nctu.edu.tw\">nplinux7</option>"
            "                  <option value=\"nplinux8.cs.nctu.edu.tw\">nplinux8</option>"
            "                  <option value=\"nplinux9.cs.nctu.edu.tw\">nplinux9</option>"
            "                  <option value=\"nplinux10.cs.nctu.edu.tw\">nplinux10</option>"
            "                  <option value=\"nplinux11.cs.nctu.edu.tw\">nplinux11</option>"
            "                  <option value=\"nplinux12.cs.nctu.edu.tw\">nplinux12</option>"
            "                </select>"
            "                <div class=\"input-group-append\">"
            "                  <span class=\"input-group-text\">.cs.nctu.edu.tw</span>"
            "                </div>"
            "              </div>"
            "            </td>"
            "            <td>"
            "              <input name=\"p";
            header += to_string(i);
            header += "\" type=\"text\" class=\"form-control\" size=\"5\" />";
            header += 
            "            </td>"
            "            <td>"
            "              <select name=\"f";
            header += to_string(i);
            header += "\" class=\"custom-select\">";
            header += 
            "                <option></option>"
            "                <option value=\"t1.txt\">t1.txt</option>"
            "                <option value=\"t2.txt\">t2.txt</option>"
            "                <option value=\"t3.txt\">t3.txt</option>"
            "                <option value=\"t4.txt\">t4.txt</option>"
            "                <option value=\"t5.txt\">t5.txt</option>"
            "              </select>"
            "            </td>"
            "          </tr>";
        }
        header +=
        "          <tr>"
        "            <td colspan=\"3\"></td>"
        "            <td>"
        "              <button type=\"submit\" class=\"btn btn-info btn-block\">Run</button>"
        "            </td>"
        "          </tr>"
        "        </tbody>"
        "      </table>"
        "    </form>"
        "  </body>"
        "</html>";

        boost::asio::async_write(socket_, buffer(header.c_str(), header.length()), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                // do nothing...
            }
        });
    }

    void getRemoteServerInfo(){
        // split each server information
        vector<string> infos = {}, infos_split = {};
        boost::split(infos, required_env["_QUERY_STRING"], boost::is_any_of("&"), boost::token_compress_on);
        for(auto it:infos){
            size_t start = 0;
            start = it.find_first_of('=', 0);
            if((start+1) == it.size()){
                break;
            }
            infos_split.push_back(it.substr(start+1));
        }
        int total_server = infos_split.size() / 3;
        int infos_split_index = 0;
        for(int i=0; i<total_server; i++){
            rsInfo[i+1].id = to_string(i+1);
            rsInfo[i+1].host_name = infos_split[infos_split_index++];
            rsInfo[i+1].host_port = infos_split[infos_split_index++];
            rsInfo[i+1].file_name = "test_case/" + infos_split[infos_split_index++];
        }
        return;
    }

    void getHeaderOutput(){
        auto self(shared_from_this());
        string header = "";
        header += 
        "HTTP/1.1 200 OK\r\n"
        "Content-type: text/html\r\n\r\n"
        "<!DOCTYPE html>"
        "<html lang=\"en\">"
        "  <head>"
        "    <meta charset=\"UTF-8\" />"
        "    <title>NP Project 3 Sample Console</title>"
        "    <link"
        "      rel=\"stylesheet\""
        "      href=\"https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css\""
        "      integrity=\"sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2\""
        "      crossorigin=\"anonymous\""
        "    />"
        "    <link"
        "      href=\"https://fonts.googleapis.com/css?family=Source+Code+Pro\""
        "      rel=\"stylesheet\""
        "    />"
        "    <link"
        "      rel=\"icon\""
        "      type=\"image/png\""
        "      href=\"https://cdn0.iconfinder.com/data/icons/small-n-flat/24/678068-terminal-512.png\""
        "    />"
        "    <style>"
        "      * {"
        "        font-family: 'Source Code Pro', monospace;"
        "        font-size: 1rem !important;"
        "      }"
        "      body {"
        "        background-color: #212529;"
        "      }"
        "      pre {"
        "        color: #FF63FF;"
        "      }"
        "      b {"
        "        color: #6EFFFF;"
        "      }"
        "    </style>"
        "  </head>"
        "  <body>"
        "    <table class=\"table table-dark table-bordered\">"
        "      <thead>"
        "        <tr>";
        for(auto it:rsInfo){
            header += "          <th scope=\"col\">";
            header += it.second.host_name;
            header += ":";
            header += it.second.host_port;
            header += "</th>";
        }
        header += 
        "        </tr>"
        "      </thead>"
        "      <tbody>"
        "        <tr>";
        for(auto it:rsInfo){
            header +=  "<td><pre id=\"s" + it.second.id + "\" class=\"mb-0\"></pre></td>";
        }
        header += 
        "        </tr>"
        "      </tbody>"
        "    </table>"
        "  </body>"
        "</html>";
        boost::asio::async_write(socket_, buffer(header.c_str(), header.length()), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                // do nothing...
            }
        });
    }

    void doShellSession(){
        auto self(shared_from_this());
        shared_ptr<tcp::socket> socket_ptr = make_shared<tcp::socket>(move(socket_));
        // global_socket ptr = make_shared<tcp::socket>(move(socket_));
        for(auto it:rsInfo){
            tcp::resolver::query query(it.second.host_name, it.second.host_port); // convert address & port into socket's form
            //shared_ptr<tcp::socket> _socket = make_shared<tcp::socket>(io_context_);
            //tcp::socket _socket(io_context);
            make_shared<Shellsession>(socket_ptr, move(query), it.second.id, it.second.file_name)->start();
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

    // prevent zombie process
    signal(SIGCHLD, SIG_IGN);
    
    server s(port);
    io_context_.run();

    return 0;
}