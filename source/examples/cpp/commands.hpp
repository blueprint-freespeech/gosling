#pragma once

namespace hw {
    void help(const vector<string>& args);
    void init_context(const vector<string>& args);
    void start_identity(const vector<string>& args);
    void stop_identity(const vector<string>& args);
    void request_endpoint(const vector<string>& args);
    void start_endpoint(const vector<string>& args);
    void stop_endpoint(const vector<string>& args);
    void connect_endpoint(const vector<string>& args);
    void drop_peer(const vector<string>& args);
    void list_peers(const vector<string>& args);
    void chat(const vector<string>& args);
    void exit(const vector<string>&);
}