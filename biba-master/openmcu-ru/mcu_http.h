// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#pragma once

#include <string>
#include <memory>

class MCUHTTPResponse {
public:
    enum Status {
        OK = 0,
        NO_MEMORY = 1,
        FAILED = 2,
        TIMEOUT = 3,
        FAILED_TO_RESOLVE_HOST = 4,
        CONNECTION_REFUSED = 5,
    };

    MCUHTTPResponse(int code, std::string body, Status status)
        : code(code)
        , body(body)
        , status(status)
    {
    }
    ~MCUHTTPResponse() {}

    int code;
    std::string body;
    Status status;

    // Set if a session token was provided in response headers
    std::string ccpSessionToken = "";
};


namespace MCUHTTPClient {
void Init();
void Stop();

std::unique_ptr<MCUHTTPResponse> Get(const std::string& url);
std::unique_ptr<MCUHTTPResponse> Post(const std::string& url, const std::string& body);
std::unique_ptr<MCUHTTPResponse> Put(const std::string& url, const std::string& body);

std::unique_ptr<MCUHTTPResponse> GetCCP(const std::string& url, const std::string& ccpSessionToken = "");
std::unique_ptr<MCUHTTPResponse> PostCCP(const std::string& url, const std::string& body, const std::string& ccpSessionToken = "");
std::unique_ptr<MCUHTTPResponse> GetEc2Metadata(const std::string& path);
};
