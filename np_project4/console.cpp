#include<iostream>
#include<fstream>
#include<vector>
#include<string>
#include<map>
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

io_context io_context_; 

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

/* global variable */

// record shell server's information
map<int, struct serverInfo> rsInfo;
// record socks server's information
string socks_name = "";
int socks_port;

class Shellsession : public enable_shared_from_this<Shellsession>{
public:
    Shellsession(tcp::socket socket, string id, string filename)
        : _socket(move(socket)), _id(id), _file(filename){
            get_total_cmd();
        }

    void start(){
        do_read(); // get socket's information;
    }
private:
    int cmd_count = 0;
    tcp::socket _socket;
    string _id;
    string _file;
    enum { max_length = 10240 };
    char data_[max_length];
    vector<string> cmds = {};

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
        escape(ddata);
        string output_data = "";
        output_data += "<script>document.getElementById('s" + _id + "')";
        output_data += ".innerHTML += '" + ddata + "';</script>";
        cout<<output_data<<flush;
    }

    void output_command(string ddata){
        escape(ddata);
        string output_data = "";
        output_data += "<script>document.getElementById('s" + _id + "')";
        output_data += ".innerHTML += '<b>" + ddata + "</b>';</script>";
        cout<<output_data<<flush;
    }

    void do_read(){
        /*
            bug: it need to clear the input buffer, if not, it will
            cause error and diffcult to debug, like me ...
        */
        memset(data_, '\0', max_length);
        auto self(shared_from_this());
        _socket.async_read_some(boost::asio::buffer(data_, max_length), [this, self](boost::system::error_code ec, size_t length){
            if(!ec){
                string _data(data_);
                output_shell(_data); // output from remote shell
                if(find(_data.begin(), _data.end(), '%') != _data.end()){
                    string write_command;
                    write_command = cmds[cmd_count++];
                    output_command(write_command);
                    // first time forget to write command to socks server
                    _socket.write_some(buffer(write_command));
                }
                do_read();
            }
        });
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

class Shellserver{
    public:
        Shellserver(){
            do_resolve();
        }
    
    private:
        tcp::resolver socks_server{io_context_};
        tcp::resolver shell_server{io_context_};
        tcp::socket *_socket[5];
        unsigned char packet_format[8];

        void do_resolve(){
            for(auto it:rsInfo){
                tcp::resolver::query query(socks_name, to_string(socks_port));
                socks_server.async_resolve(query, boost::bind(&Shellserver::do_resolve_handler, this, it.second.id, boost::asio::placeholders::error, boost::asio::placeholders::iterator));
            }
        }

        void do_resolve_handler(string _id, boost::system::error_code ec, tcp::resolver::iterator it){
            tcp::resolver::query query(rsInfo[stoi(_id)].host_name, rsInfo[stoi(_id)].host_port);
            tcp::endpoint socks_endpoint = *it;
            shell_server.async_resolve(query, boost::bind(&Shellserver::do_connect, this, _id, socks_endpoint, boost::asio::placeholders::error, boost::asio::placeholders::iterator));
        }

        void do_connect(string _id, tcp::endpoint socks_endpoint, boost::system::error_code ec, tcp::resolver::iterator it){
            if(!ec){
                _socket[stoi(_id)-1] = new tcp::socket(io_context_);
                tcp::endpoint shell_endpoint = *it;
                (*_socket[stoi(_id)-1]).async_connect(socks_endpoint, boost::bind(&Shellserver::do_connect_handler, this, _id, rsInfo[stoi(_id)].file_name, shell_endpoint, boost::asio::placeholders::error));
            }
        }

        void do_connect_handler(string _id, string file_name, tcp::endpoint shell_endpoint, boost::system::error_code ec){
            if(!ec){
                vector<string> ip_record = {};
                string ip = shell_endpoint.address().to_string();
                boost::split(ip_record, ip, boost::is_any_of("."), boost::token_compress_on);
                packet_format[0] = 0x04;
                packet_format[1] = 0x01;
                packet_format[2] = shell_endpoint.port() / 256;
                packet_format[3] = shell_endpoint.port() % 256;
                packet_format[4] = (unsigned char)atoi(ip_record[0].c_str());
                packet_format[5] = (unsigned char)atoi(ip_record[1].c_str());
                packet_format[6] = (unsigned char)atoi(ip_record[2].c_str());
                packet_format[7] = (unsigned char)atoi(ip_record[3].c_str());

                // for(int i=0;i<8;i++){
                //     cout<<packet_format[i]<<endl;
                // }

                (*_socket[stoi(_id)-1]).async_send(boost::asio::buffer(packet_format, 8), [this, _id, file_name](boost::system::error_code ec, size_t length){
                    if(!ec){
                        (*_socket[stoi(_id)-1]).async_read_some(boost::asio::buffer(packet_format, 8), [this, _id, file_name](boost::system::error_code ec2, size_t length2){
                            if(!ec2){
                                make_shared<Shellsession>(move(*_socket[stoi(_id)-1]), _id, file_name) -> start();
                            }
                        });
                    }
                });
            }
        }
};

void getRemoteServerInfo(){
    string query_str = string(getenv("QUERY_STRING"));
    // split each server information
    vector<string> infos = {}, infos_split = {};
    boost::split(infos, query_str, boost::is_any_of("&"), boost::token_compress_on);
    for(auto it:infos){
        size_t start = 0;
        start = it.find_first_of('=', 0);
        if((start+1) == it.size()){
            continue;
        }
        infos_split.push_back(it.substr(start+1));
    }
    int total_server = infos_split.size() / 3;
    int infos_split_index = 0;
    // shell server's information
    for(int i=0; i<total_server; i++){
        rsInfo[i+1].id = to_string(i+1);
        rsInfo[i+1].host_name = infos_split[infos_split_index++];
        rsInfo[i+1].host_port = infos_split[infos_split_index++];
        rsInfo[i+1].file_name = "test_case/" + infos_split[infos_split_index++];
    }
    // socks server's information
    socks_name = infos_split[infos_split_index++];
    socks_port = stoi(infos_split[infos_split_index++]);
    return;
};

void getHeaderOutput(){
    cout<<"Content-type: text/html\r\n\r\n"<<flush;
    string header = "";
    header +=
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
    cout<<header<<flush;
    return;
};

int main(int argc, char* argv[]){
    
    getRemoteServerInfo();
    getHeaderOutput();
    Shellserver _Shellserver;
    io_context_.run();
    return 0;
}