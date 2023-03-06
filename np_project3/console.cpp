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
#include<boost/algorithm/string/split.hpp> // boost split
#include<boost/algorithm/string/replace.hpp> // replace_all
#include<boost/algorithm/string/classification.hpp> // is_any_of

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ip;

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
// global variable
map<int, struct serverInfo> rsInfo;

class Shellsession : public enable_shared_from_this<Shellsession>{
public:
    Shellsession(io_context& io_context, tcp::resolver::query query, string id, string filename)
        : _resolver(io_context), _socket(io_context), _query(move(query)), _id(id), _file(filename){
            get_total_cmd();
        }

    void start(){
        do_resolve_connect(); // get socket's information;
    }
private:
    int cmd_count = 0;
    tcp::resolver _resolver;
    tcp::socket _socket;
    tcp::resolver::query _query;
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
                        _socket.write_some(buffer(write_command));
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
                    _socket.async_connect(*it, [this, self](boost::system::error_code ec){
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
}

void getRemoteServerInfo(){
    string query_str = string(getenv("QUERY_STRING"));
    // split each server information
    vector<string> infos = {}, infos_split = {};
    boost::split(infos, query_str, boost::is_any_of("&"), boost::token_compress_on);
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

int main(int argc, char* argv[]){
    // parse the query string
    getRemoteServerInfo();
    // header output
    getHeaderOutput();
    
    // io context
    io_context io_context;
    for(auto it:rsInfo){
        tcp::resolver::query query(it.second.host_name, it.second.host_port); // convert address & port into socket's form
        make_shared<Shellsession>(io_context, move(query), it.second.id, it.second.file_name)->start();
    }
    io_context.run();
    return 0;
}