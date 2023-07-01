// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#include "mcu.h"
#include "ptclib/random.h"
#include <curl/curl.h>
#include <memory>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <regex>

const long kTimeoutMs = 10 * 1000;
const int kMaxAttempts = 6;
const int kBaseSleepMs = 250;

const std::string kJsonContentType = "Content-Type: application/json; charset=utf-8";
const std::string kJsonAccept = "Accept: application/json";
const std::string kEmptyExpect = "Expect:";
const std::string kDefaultUserAgent = "Biba/1.0 Internal API Consumer";
const std::string kCCPSessionCookieName = "_aws_wt_session";

//provide function prototype declaration before its usage
void add_sigv4_header(CURL* curl, 
    const std::string& access_key_id, 
    const std::string& secret_access_key, 
    const std::string& region, 
    const std::string& service, 
    const std::string& method, 
    const std::string& endpoint, 
    const std::string& path, 
    const std::string& query_params, 
    const std::string& body
);
std::string sign(const std::string& key, const std::string& data);
std::string extractIPAddress(const std::string& url);
std::string extractHTTPPath(const std::string& url);

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

    //prepare sigv4 header
    std::string access_key_id;
    std::string secret_access_key;
    std::string path = "/credentials"; // need edit
    // std::unique_ptr<MCUHTTPResponse> creds_response = MCUHTTPClient::GetEc2Metadata(""); //put "" to check if can fetch metadata
    // if (creds_response->status == MCUHTTPResponse::OK) {
    //     std::string responseBody = creds_response->body;
    //     std::cout << "test0626 GetEc2Metadata response" << responseBody << "is end" << std::endl;
    //     Json::Value root;
    //     if (Json::Reader().parse(responseBody, root)) { 
    //         //access_key_id = root["AccessKeyId"].asString();
    //         //secret_access_key = root["SecretAccessKey"].asString();
    //         access_key_id = "ASIA2ECVQARU2DLHDNLU";
    //         secret_access_key = "5D06cITCLWxD5mw3u/ugKBO90viTrfr3BdFoiI0e";
    //     } else {
    //         PTRACE(PTrace::Level::Error, "failed to parse JSON creds_response from GetEc2Metadata");
    //         return std::make_unique<MCUHTTPResponse>(0, "", MCUHTTPResponse::FAILED);
    //     }
    // } else {
    //     PTRACE(PTrace::Level::Error, "failed to get creds_response from GetEc2Metadata");
    //     return std::make_unique<MCUHTTPResponse>(0, "", MCUHTTPResponse::FAILED);
    // }
    access_key_id = "ASIA2ECVQARUU6AHU3GV";
    secret_access_key = "uUTQ3DkUv+jkS8xvudM9HQ07tfhpsZVM9ax2Lzmb";

    std::string strTail = "/anonymous_sessions";
    if(url.length() >= strTail.length() &&
            url.compare(url.length() - strTail.length(), strTail.length(), strTail) == 0) { //check if url end up with /anonymous_sessions

        std::string serviceName = "ucccp";  // need edit
        //std::string serviceName = MCUConfig("Biba").GetString(ServiceNameKey);
        std::cout << "test0626 serviceName " << serviceName << " is end" << std::endl;
       
        std::string region = "us-east-1"; // need edit
        //std::string region = MCUConfig("Parameters").GetString(Region).operator std::string();
        std::cout << "test0626 region " << region << " is end" << std::endl;
        
        std::cout << "test0626 url " << url << " is end" << std::endl;
        std::string ip_name = "ccp.cp.ue1.a.app.chime.aws"; // need edit
        //std::string ip_name = extractIPAddress(url);
        std::cout << "test0626 Extracted IP address: " << ip_name << " is end" << std::endl;
        //std::path = "";

        std::string path = "/anonymous_sessions";
        //std::string path = extractHTTPPath(url);
        std::cout << "test0626 Extracted HTTP path: " << path << std::endl;
        add_sigv4_header(curl, access_key_id, secret_access_key, region, serviceName, "PUT", ip_name, path, "", body);
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
    PTRACE(PTrace::Level::Info, "doRequest http client " << method << "  " << url << " returned " << responseCode << " status " << responseStatus);
    PTRACE(PTrace::Level::Info, "doRequest http client " << "responseBody" << responseBody);
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
        PTRACE(PTrace::Level::Info, "doRequestWithRetry body is" << body);
        PTRACE(PTrace::Level::Info, "doRequestWithRetry url is" << url);
        PTRACE(PTrace::Level::Info, "doRequestWithRetry header is" << header);
        PTRACE(PTrace::Level::Info, "doRequestWithRetry isCCP is" << isCCP);
        PTRACE(PTrace::Level::Info, "doRequestWithRetry ccpSessionToken is" << ccpSessionToken);

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

void add_sigv4_header(CURL* curl, 
    const std::string& access_key_id, 
    const std::string& secret_access_key, 
    const std::string& region, 
    const std::string& service, 
    const std::string& method, 
    const std::string& endpoint, 
    const std::string& path, 
    const std::string& query_params, 
    const std::string& body
) { 
    // prepare datetime string
    time_t now = time(nullptr); 
    struct tm gm_time; 
    gmtime_r(&now, &gm_time); 
    char date[9], datetime[17]; 
    strftime(date, sizeof(date), "%Y%m%d", &gm_time);
    strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%SZ", &gm_time); 
    
    // prepare canonical_request
    std::ostringstream oss; 
    oss << method << "\n" << path << "\n" << query_params << "\n" << "host:" << endpoint << "\n" 
    << "x-amz-content-sha256:" << sign("AWS4" + secret_access_key, body) << "\n" << "x-amz-date:" << datetime 
    << "\n\n" << "host;x-amz-content-sha256;x-amz-date\n" << sign("AWS4" + secret_access_key, ""); 
    std::string canonical_request = oss.str(); 
    std::cout << "test0626 canonical_request is: " << canonical_request << " is end" << std::endl;
    
    // prepare stringToSign
    std::ostringstream oss2; 
    oss2 << "AWS4-HMAC-SHA256\n" << datetime << "\n" << date << "/" << region << "/" 
    << service << "/aws4_request\n" << sign("AWS4" + secret_access_key, date) << "\n" << canonical_request; 
    std::string string_to_sign = oss2.str(); 
    std::cout << "test0626 string+to_sign" << string_to_sign << "is end" << std::endl;
    
    // prepare signature
    std::string signature = sign(sign(sign(sign("AWS4" + secret_access_key, date), region), service), "aws4_request" + string_to_sign); 
    std::cout << "test0626 signature" << signature << "is end" << std::endl;
    
    // prepare authorization_header
    std::ostringstream oss3; 
    oss3 << "AWS4-HMAC-SHA256 Credential=" << access_key_id << "/" << date << "/" << region << "/" 
    << service << "/aws4_request, SignedHeaders=accept;content-type;host;x-amz-date;x-amz-security-token," << " Signature=" << signature; 
    std::string authorization_header = oss3.str(); 
    std::cout << "test0626 authorization_header " << authorization_header << "is end" << std::endl;
    
    // construct authorization_header into HTTP request header
    struct curl_slist* headers = nullptr; 
    headers = curl_slist_append(headers, ("Authorization: " + authorization_header).c_str()); 
    headers = curl_slist_append(headers, ("X-Amz-Content-Sha256: " + sign("AWS4" + secret_access_key, body)).c_str());
    headers = curl_slist_append(headers, ("X-Amz-Date: " + std::string(datetime)).c_str()); 
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
} 

//sha256 helper
std::string sign(const std::string& key, const std::string& data) { 
    unsigned char* digest 
        = HMAC(EVP_sha256(), key.c_str(), key.size(), 
        reinterpret_cast<const unsigned char*>(data.c_str()), 
        data.size(), nullptr, nullptr); 
    std::stringstream ss; 
    
    for (int i = 0; i < EVP_MD_size(EVP_sha256()); ++i) { 
        ss << std::hex << static_cast<int>(digest[i]); 
    } 
    
    return ss.str();
} 

std::string extractIPAddress(const std::string& url) {
    std::regex ipRegex(R"(http://([\d]+\.[\d]+\.[\d]+\.[\d]+))");
    std::smatch match;
    
    if (std::regex_search(url, match, ipRegex)) {
        return match[1].str();
    }
    
    return "";
}

std::string extractHTTPPath(const std::string& url) {
    std::regex pathRegex(R"(http://[\d]+\.[\d]+\.[\d]+\.[\d]+(/[\w/]+)*)");
    std::smatch match;
    
    if (std::regex_search(url, match, pathRegex)) {
        return match[1].str();
    }
    
    return "";
}
