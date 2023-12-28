#pragma once

namespace hw {
    void help(vector<string> args);
    void init_context(vector<string> args);
    void start_identity(vector<string> args);
    void stop_identity(vector<string> args);
    void request_endpoint(vector<string> args);
    void start_endpoint(vector<string> args);
    void stop_endpoint(vector<string> args);
    void connect_endpoint(vector<string> args);
    void drop_peer(vector<string> args);
    void list_peers(vector<string> args);
    void chat(vector<string> args);
    void exit(vector<string>);
}