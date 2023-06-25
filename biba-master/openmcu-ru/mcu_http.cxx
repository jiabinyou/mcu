// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#include "mcu.h"
#include "ptclib/random.h"
#include <curl/curl.h>
#include <memory>

const long kTimeoutMs = 10 * 1000;
const int kMaxAttempts = 6;
const int kBaseSleepMs = 250;

const std::string kJsonContentType = "Content-Type: application/json; charset=utf-8";
const std::string kJsonAccept = "Accept: application/json";
const std::string kEmptyExpect = "Expect:";
const std::string kDefaultUserAgent = "Biba/1.0 Internal API Consumer";
const std::string kCCPSessionCookieName = "_aws_wt_session";

namespace {

static size_t writer(char* data, size_t size, size_t nmemb, std::string* w)
{
    if (!w)
        return 0;
    w->append(data, size * nmemb);
    return size * nmemb;
}

MCUHTTPResponse::Status performRequest(CURL* curl, long* status)
{
    CURLcode curlStatus = curl_easy_perform(curl);
    if (curlStatus != CURLE_OK) {
        PTRACE(PTrace::Level::Error, "http request failed: " << curl_easy_strerror(curlStatus));
        switch (curlStatus) {
        case CURLE_OPERATION_TIMEDOUT:
            return MCUHTTPResponse::TIMEOUT;
        case CURLE_COULDNT_RESOLVE_HOST:
            return MCUHTTPResponse::FAILED_TO_RESOLVE_HOST;
        case CURLE_COULDNT_CONNECT:
            return MCUHTTPResponse::CONNECTION_REFUSED;
        default:
            return MCUHTTPResponse::FAILED;
        }
    }

    curlStatus = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    if (curlStatus != CURLE_OK) {
        PTRACE(PTrace::Level::Error, "could not get response code from http response: " << curl_easy_strerror(curlStatus));
        return MCUHTTPResponse::FAILED;
    }
    return MCUHTTPResponse::OK;
}

std::string getCCPSessionToken(CURL* curl)
{
    struct curl_slist* cookie_list = NULL;
    CURLcode curlStatus = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookie_list);
    if (curlStatus != CURLE_OK) {
        PTRACE(PTrace::Level::Error, "failed to retrieve cookies from http response: " << curl_easy_strerror(curlStatus));
        return "";
    }

    PString name(kCCPSessionCookieName);
    std::string ccpSessionToken;
    for (struct curl_slist* n = cookie_list; n; n = n->next) {
        PStringArray tokens = PString(n->data).Tokenise('\t');
        if (tokens.GetSize() >= 7 && tokens[5] == name) {
            ccpSessionToken.assign((const char*)tokens[6]);
        }
    }
    curl_slist_free_all(cookie_list);
    return ccpSessionToken;
}

std::unique_ptr<MCUHTTPResponse> doRequest(const std::string& method, const std::string& url, const std::string& body,
    const std::string& header, bool isCCP, const std::string& ccpSessionToken)
{
    CURL* curl = curl_easy_init();
    if (!curl) return std::make_unique<MCUHTTPResponse>(0, "", MCUHTTPResponse::NO_MEMORY);

    struct curl_slist* headers = NULL;
    if (body.length() > 0 && (method == "POST" || method == "PUT")) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        if (isCCP) headers = curl_slist_append(headers, kJsonContentType.c_str());
    }

    if (isCCP) {
        if (ccpSessionToken.length() > 0) {
            curl_easy_setopt(curl, CURLOPT_COOKIE, (kCCPSessionCookieName + "=" + ccpSessionToken).c_str());
        }
        headers = curl_slist_append(headers, kJsonAccept.c_str());
        headers = curl_slist_append(headers, kEmptyExpect.c_str());
    } 
    if (!header.empty()) {
        headers = curl_slist_append(headers, header.c_str());
    }
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, kTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, kDefaultUserAgent.c_str());
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, ""); // Get the cookie engine started
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); // Needed for multi-threaded applications

    std::string responseBody;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);

    long responseCode = 0;
    MCUHTTPResponse::Status responseStatus = performRequest(curl, &responseCode);
    auto response = std::make_unique<MCUHTTPResponse>(responseCode, responseBody, responseStatus);
    PTRACE(PTrace::Level::Info, "http client " << method << "  " << url << " returned " << responseCode << " status " << responseStatus);
    if (isCCP && responseCode / 100 == 2) {
        response->ccpSessionToken = getCCPSessionToken(curl);
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return response;
}

bool shouldRetry(MCUHTTPResponse response)
{
    return (response.status == MCUHTTPResponse::OK && (response.code / 100 == 5 || response.code == 429))
        || response.status == MCUHTTPResponse::TIMEOUT
        || response.status == MCUHTTPResponse::FAILED_TO_RESOLVE_HOST
        || response.status == MCUHTTPResponse::CONNECTION_REFUSED;
}

std::unique_ptr<MCUHTTPResponse> doRequestWithRetry(const std::string& method, const std::string& url, const std::string& body,
    const std::string& header, bool isCCP, const std::string& ccpSessionToken)
{
    std::unique_ptr<MCUHTTPResponse> response = std::make_unique<MCUHTTPResponse>(0, "", MCUHTTPResponse::FAILED);
    for (int i = 0; i < kMaxAttempts; i++) {
        response = doRequest(method, url, body, header, isCCP, ccpSessionToken);

        if (!shouldRetry(*response.get())) break;
        if (response.get()->status != MCUHTTPResponse::TIMEOUT) {
            int delay = (1 << i) * kBaseSleepMs + PRandom::Number(kBaseSleepMs);
            PThread::Sleep(delay);
        }
    }
    return response;
}
}

void MCUHTTPClient::Init()
{
    curl_global_init(CURL_GLOBAL_ALL);
}

void MCUHTTPClient::Stop()
{
    curl_global_cleanup();
}

std::unique_ptr<MCUHTTPResponse> MCUHTTPClient::Get(const std::string& url)
{
    std::string dummyToken = "";
    return doRequestWithRetry("GET", url, "", "", false, dummyToken);
}

std::unique_ptr<MCUHTTPResponse> MCUHTTPClient::Post(const std::string& url, const std::string& body)
{
    std::string dummyToken = "";
    return doRequestWithRetry("POST", url, body, "", false, dummyToken);
}

std::unique_ptr<MCUHTTPResponse> MCUHTTPClient::Put(const std::string& url, const std::string& body)
{
    std::string dummyToken = "";
    return doRequestWithRetry("PUT", url, body, "", false, dummyToken);
}

std::unique_ptr<MCUHTTPResponse> MCUHTTPClient::GetCCP(const std::string& url, const std::string& ccpSessionToken)
{
    return doRequestWithRetry("GET", url, "", "", true, ccpSessionToken);
}

std::unique_ptr<MCUHTTPResponse> MCUHTTPClient::PostCCP(const std::string& url, const std::string& body, const std::string& ccpSessionToken)
{
    return doRequestWithRetry("POST", url, body, "", true, ccpSessionToken);
}

std::unique_ptr<MCUHTTPResponse> MCUHTTPClient::GetEc2Metadata(const std::string& path)
{
    auto putResponse = doRequestWithRetry("PUT", "http://169.254.169.254/latest/api/token", "", "X-aws-ec2-metadata-token-ttl-seconds: 21600", false, "");
    if (putResponse->body.empty()) {
        return putResponse;
    }

    const std::string token = putResponse->body;
    const std::string url = "http://169.254.169.254/latest/meta-data" + path;
    const std::string tokenHeader = "X-aws-ec2-metadata-token: " + token;
    return doRequestWithRetry("GET", url, "", tokenHeader, false, "");
}
