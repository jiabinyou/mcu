// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#include <uuid/uuid.h>

#include "ptlib.h"
#include "ptclib/cypher.h"
#include "ptclib/random.h"

#include "queryLogs/EasyQueryLogger.h"
#include "ccp.h"
#include "mcu.h"
#include "biba_bridge_adapter.h"

#include <iostream>   // for input/output
#include <cstring>    // for string manipulation
#include <openssl/hmac.h>  // for HMAC functions
#include <openssl/sha.h>   // for SHA256 functions

#include <rtc_base/string_encode.h>

namespace {

std::string baseUrl_;
std::string accessKey;
std::string secretKey;
std::string sessionToken;
std::string dateTimeStamp = PTime().AsString("yyyyMMddTHHmmssZ");
std::string signingRegion = "<signing-region>"; // need edit

std::string buildAuthRequestBody(const std::string& passcode,
    const std::string& username,
    const MCUConnectionTypes& connectionType,
    const std::string& connectionId)
{
    // For CCP, we should try to use the same device ID as much as we could
    // if the request is from the same device. username (H323 remote party
    // name) can be used for this purpose. If it turns out the remote party
    // name is too generic to identy a device, we may switch to use the
    // member name created in MCUH323Connection.

    // The device ID is used as the local part of the email address of an
    // anonymous profile.
    EasyQueryLogger::scoped_operation authOperation("CCPClient::0626buildAuthRequestBody");
    PTRACE(PTrace::Level::Info, "CCPClient\t0626PTRACEbuildAuthRequestBody");
    PString pname = username;
    PString deviceId = BibaBridgeAdapter::SHA256(pname);
    std::string deviceType = "";
    std::string region = MCUConfig("Parameters").GetString(Region).operator std::string();

    if (connectionType == CONNECTION_TYPE_H323) {
        deviceType = "h323";
    } else if (connectionType == CONNECTION_TYPE_SIP) {
        deviceType = "sip";
    }

    Json::Value root;
    root["anonymous_session"]["passcode"] = passcode;
    root["anonymous_session"]["full_name"] = username;
    root["anonymous_session"]["device_type"] = deviceType;
    root["anonymous_session"]["device_platform"] = "h323";
    root["anonymous_session"]["device_id"] = deviceId.operator std::string();
    root["anonymous_session"]["user_agent"] = username;
    root["anonymous_session"]["origin_conn_id"] = connectionId;
    root["anonymous_session"]["region"] = region;
    Json::FastWriter writer;
    PTRACE(PTrace::Level::Info, "CCPClient\t0626PTRACEwriteAuthRequestBody");

    return writer.write(root);
}

std::string computeHMAC(const std::string& secretKey, const std::string& data) {
    unsigned char* digest;
    unsigned int digestLength;

    digest = HMAC(EVP_sha256(), secretKey.c_str(), secretKey.length(), reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), NULL, &digestLength);
    
    std::string result(reinterpret_cast<char*>(digest), digestLength);
    
    // Clean up the digest memory
    OPENSSL_free(digest);

    return result;
}

std::string computeHash(const std::string& secretKey, const std::string& simpleDate, const std::string& region, const std::string& serviceName) {
    std::string signingKey = "AWSAuthHelper::SIGNING_KEY" + secretKey;
    std::string kDate = computeHMAC(signingKey, simpleDate);
    std::string kRegion = computeHMAC(kDate, region);
    std::string kService = computeHMAC(kRegion, serviceName);
    std::string kRequest = computeHMAC(kService, "AWS4_REQUEST");

    return kRequest;
}

std::string generateSigV4Signature(const std::string& passcode,
    const std::string& username,
    const MCUConnectionTypes& connectionType,
    const std::string& connectionId)
{
    //prepare canonicalRequest string
    std::string host  = "";  //need edit
    std::string body = buildAuthRequestBody(passcode, username, connectionType, connectionId);
    std::string canonicalRequest = std::string("POST") + std::string("\n") +
        std::string("/anonymous_sessions\n") +
        std::string("\n") +
        std::string("content-type:application/json\n") +
        std::string("host:") + host + "\n" +
        std::string("x-amz-date:") + dateTimeStamp + std::string("\n") +
        std::string("\n") +
        std::string("content-type;host;x-amz-date\n") +
        rtc::hex_encode(body);

    //prepare credentials
    std::string path = "/credentials"; // figure out Path for retrieving credentials
    std::unique_ptr<MCUHTTPResponse> response = MCUHTTPClient::GetEc2Metadata(path);
    if (response->status == MCUHTTPResponse::OK) {
        std::string responseBody = response->body;

        // Parse the response body to extract the credentials
        // Assuming the response body is in JSON format
        Json::Value root;
        if (Json::Reader().parse(responseBody, root)) { 
            accessKey = root["AccessKeyId"].asString();
            secretKey = root["SecretAccessKey"].asString();
            sessionToken = root["Token"].asString();
        } else {
            // Failed to parse the response body as JSON
            // Handle the error accordingly
        }
    } else {
        // Failed to retrieve credentials from metadata service
        // Handle the error accordingly
    }

    //prepare stringToSign   
    std::string simpleDate = PTime().AsString("yyyyMMddTHHmmssZ");
    //std::string kSecret = "AWS4" + secretKey;
    //std::string kDate = PTime().AsString("yyyyMMdd");
    //std::string signingRegion = "<signing-region>"; // need edit
    std::string signingServiceName = "execute-api";
    //std::string kSigning = "aws4_request";
    std::string canonicalRequestHash = rtc::hex_encode(canonicalRequest);

    std::string hashAlgorithm = "AWS4-HMAC-SHA256";
    //std::string stringToSign = hashAlgorithm + "\n" + dateTimeStamp + "\n" + simpleDate + "/" + signingRegion + "/" + signingServiceName + "/" + kSigning + "\n" + canonicalRequestHash;
    std::string stringToSign = hashAlgorithm + "\n" + dateTimeStamp + "\n" + simpleDate + "/" + signingRegion + "/" + signingServiceName + "\n" + canonicalRequestHash;


    //prepare signature
    std::string key = computeHash(secretKey, simpleDate, signingRegion, signingServiceName);

    std::string signature = computeHMAC(key, stringToSign);
    std::stringstream ss;
    ss << signature;
    return ss.str();
}

std::string buildAuthenticationHeader(const std::string& passcode,
    const std::string& username,
    const MCUConnectionTypes& connectionType,
    const std::string& connectionId)
{
    std::string signature = generateSigV4Signature(passcode, username, connectionType, connectionId);
    std::string authorizationHeader = "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + dateTimeStamp + "/" + signingRegion + "/execute-api/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=" + signature;
    return authorizationHeader;
}

std::string buildFeedbackRequestBody(const std::string& callId,
    const int thumbsUp,
    const std::string& comment)
{
    Json::Value root;
    root["ConferenceId"] = callId;
    root["Context"] = "EndOfCall";
    root["Type"] = "ThumbsUpDownWithComments";
    root["Email"] = "anon.mcu.caller@app.chime.aws";
    root["ThumbsUpDownRating"] = thumbsUp;
    if (!comment.empty()) {
        root["Comments"] = comment;
    }
    Json::FastWriter writer;
    return writer.write(root);
}

std::string buildControlCodeRequestBody(const std::string& callId,
    const std::string& controlCode)
{
    Json::Value root;
    root["MeetingId"] = callId;
    root["ControlCode"] = controlCode;

    Json::FastWriter writer;
    return writer.write(root);
}

CCPClient::Status parseAuthResponseBody(const std::string& responseBody,
    CCPAuthResponse& authResponse)
{
    if (responseBody.empty()) {
        return CCPClient::NO_BODY;
    }

    Json::Value root;
    if (!Json::Reader().parse(responseBody, root, false)) {
        PTRACE(PTrace::Level::Error, "failed to parse JSON response from ccp");
        return CCPClient::FAILED;
    }

    if (root["errors"]["meeting"][0]["code"].asUInt() == 4001) {
        return CCPClient::PIN_LOCKED;
    }
    if (root["Code"].asString() == "meeting_at_capacity") {
        return CCPClient::CAPACITY_ERROR;
    }

    authResponse.profileId = root["principal"]["id"].asString();
    authResponse.callId = root["meeting"]["call"]["id"].asString();
    authResponse.audioHost = root["meeting"]["call"]["host"].asString();
    authResponse.videoUrl = root["meeting"]["call"]["control_url"].asString();
    authResponse.bithubUrl = root["meeting"]["call"]["desktop_bithub_url"].asString();
    authResponse.stunUrl = root["meeting"]["call"]["stun_server_url"].asString();
    authResponse.isParked = root["meeting"]["park_status"] == "parked" ? true : false;
    authResponse.isEventModeEnabled = root["event_mode_enabled"].asBool();

    return CCPClient::OK;
}

CCPClient::Status parseDisplayNamesResponseBody(const std::string& responseBody,
    std::map<std::string, std::string>& display_names)
{
    if (responseBody.empty()) {
        return CCPClient::NO_BODY;
    }
    Json::Value root;
    if (!Json::Reader().parse(responseBody, root, false)) {
        PTRACE(PTrace::Level::Error, "failed to parse JSON response from ccp");
        return CCPClient::FAILED;
    }

    Json::Value& participations = root["participations"];
    for (unsigned int i = 0; i < participations.size(); ++i) {
        Json::Value& part = participations[i];
        std::string profileId = part["profile"]["id"].asString();
        display_names[profileId] = part["profile"]["full_name"].asString();
    }

    return CCPClient::OK;
}

CCPClient::Status HTTPStatusToCCPStatus(MCUHTTPResponse::Status status)
{
    switch (status) {
    case MCUHTTPResponse::OK:
        return CCPClient::OK;
    case MCUHTTPResponse::NO_MEMORY:
        return CCPClient::NO_MEMORY;
    case MCUHTTPResponse::FAILED:
        return CCPClient::FAILED;
    case MCUHTTPResponse::FAILED_TO_RESOLVE_HOST:
        return CCPClient::FAILED_TO_RESOLVE_HOST;
    case MCUHTTPResponse::CONNECTION_REFUSED:
        return CCPClient::CONNECTION_REFUSED;
    default:
        return CCPClient::FAILED;
    }
}
}

void CCPClient::Configure()
{
    baseUrl_ = MCUConfig("Biba").GetString(RelayUrlKey).operator std::string();
}

std::string CCPClient::StatusString(CCPClient::Status status)
{
    switch (status) {
    case CCPClient::OK:
        return "ok";
    case CCPClient::NO_MEMORY:
        return "noMemory";
    case CCPClient::FAILED:
        return "failed";
    case CCPClient::TIMEOUT:
        return "timeout";
    case CCPClient::NO_BODY:
        return "noBody";
    case CCPClient::ERR_RESP:
        return "errResp";
    case CCPClient::PIN_LOCKED:
        return "pinLocked";
    case CCPClient::PIN_NOT_FOUND:
        return "pinNotFound";
    case CCPClient::INVALID_SESSION_TOKEN:
        return "invalidSessionToken";
    case CCPClient::FAILED_TO_RESOLVE_HOST:
        return "failedToResolveHost";
    case CCPClient::CONNECTION_REFUSED:
        return "connectionRefused";
    default:
        return "unknown";
    }
}

CCPClient::Status CCPClient::AuthenticateViaPasscode(const std::string& passcode,
    const std::string& username,
    const MCUConnectionTypes& connectionType,
    const std::string& connectionId,
    CCPAuthResponse& authResponse)
{
    std::string url = baseUrl_ + "/anonymous_sessions";
    std::string body = buildAuthRequestBody(passcode, username, connectionType, connectionId);
    std::string header = buildAuthenticationHeader(passcode, username, connectionType, connectionId);
    PTRACE(PTrace::Level::Info, "CCPClient\tAuthenticateViaPasscode");
    PTRACE(PTrace::Level::Info, "CCPClient\t0626PTRACEAuthenticateViaPasscode");

    //std::unique_ptr<MCUHTTPResponse> response = MCUHTTPClient::PostCCP(url, body, authResponse.sessionToken);
    std::unique_ptr<MCUHTTPResponse> response = MCUHTTPClient::PostCCPWithHeader(url, body, header, authResponse.sessionToken);
    MCUHTTPResponse::Status status = response.get()->status;
    if (status != MCUHTTPResponse::OK) {
        return HTTPStatusToCCPStatus(status);
    }

    char httpResponseCodeMetric[32];
    int responseCode = response.get()->code;
    EasyQueryLogger::scoped_operation authOperation("CCPClient::0626AuthenticateViaPasscode");
    snprintf(httpResponseCodeMetric, 32, "HttpResponseStatus%03d", responseCode);
    EasyQueryLogger::counterIncrement(httpResponseCodeMetric, 1);

    if (responseCode / 100 != 2) {
        if (responseCode == 422) {
            PTRACE(PTrace::Level::Info, "In AuthenticateViaPasscode, status = " << responseCode << ", body = " << response.get()->body);
            CCPClient::Status status = parseAuthResponseBody(response.get()->body, authResponse);
            if (status == CCPClient::PIN_LOCKED || status == CCPClient::CAPACITY_ERROR) return status;
        } else if (responseCode == 404) {
            return CCPClient::PIN_NOT_FOUND;
        }
        return CCPClient::ERR_RESP;
    }

    if (response->ccpSessionToken.empty()) {
        PTRACE(PTrace::Level::Error, "CCP did not return session token from " << url);
        return CCPClient::INVALID_SESSION_TOKEN;
    }
    const CCPClient::Status ccpStatus = parseAuthResponseBody(response.get()->body, authResponse);
    authResponse.sessionToken = response->ccpSessionToken;

    return ccpStatus;
}

CCPClient::Status CCPClient::RetrieveDisplayNames(const std::string& callId,
    std::string& sessionToken,
    std::map<std::string, std::string>& displayNames)
{
    std::stringstream ss;
    ss << baseUrl_ << "/calls/" << callId << "/all_attendees";
    std::string url = ss.str();

    PTRACE(PTrace::Level::Info, "CCPClient\tRetrieveDisplayName url = " << url);
    std::unique_ptr<MCUHTTPResponse> response = MCUHTTPClient::GetCCP(url, sessionToken);
    MCUHTTPResponse::Status status = response.get()->status;
    if (status != MCUHTTPResponse::OK) {
        return HTTPStatusToCCPStatus(status);
    }

    if (response.get()->code / 100 != 2) {
        return CCPClient::ERR_RESP;
    }

    return parseDisplayNamesResponseBody(response.get()->body, displayNames);
}

CCPClient::Status CCPClient::SubmitControlCode(const std::string& callId,
    std::string& sessionToken,
    const std::string& controlCode)
{
    std::stringstream ss;
    ss << baseUrl_ << "/v2/meetings/" << callId << "/control_code";
    std::string url = ss.str();
    std::string requestBody = buildControlCodeRequestBody(callId, controlCode);

    PTRACE(PTrace::Level::Info, "CCPClient\tSubmitControlCode call = " << callId << " url = " << url);
    std::unique_ptr<MCUHTTPResponse> response = MCUHTTPClient::PostCCP(url, requestBody, sessionToken);
    MCUHTTPResponse::Status status = response.get()->status;
    if (status != MCUHTTPResponse::OK) {
        return HTTPStatusToCCPStatus(status);
    }
    if (response.get()->code / 100 != 2) {
        return CCPClient::ERR_RESP;
    }
    return CCPClient::OK;
}

CCPClient::Status CCPClient::SubmitMeetingFeedback(const std::string& callId,
    std::string& sessionToken,
    const int thumbsUp,
    const std::string& comment)
{
    std::stringstream ss;
    ss << baseUrl_ << "/feedback/" << callId;
    std::string url = ss.str();
    std::string requestBody = buildFeedbackRequestBody(callId, thumbsUp, comment);

    PTRACE(PTrace::Level::Info, "CCPClient\tSubmitMeetingFeedback call = " << callId << " url = " << url);
    std::unique_ptr<MCUHTTPResponse> response = MCUHTTPClient::PostCCP(url, requestBody, sessionToken);
    MCUHTTPResponse::Status status = response.get()->status;
    if (status != MCUHTTPResponse::OK) {
        return HTTPStatusToCCPStatus(status);
    }
    if (response.get()->code / 100 != 2) {
        return CCPClient::ERR_RESP;
    }
    return CCPClient::OK;
}
