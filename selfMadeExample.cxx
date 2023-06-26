#include <uuid/uuid.h>

#include "ptlib.h"
#include "ptclib/cypher.h"
#include "ptclib/random.h"

#include "queryLogs/EasyQueryLogger.h"
#include "ccp.h"
#include "mcu.h"
#include "biba_bridge_adapter.h"

namespace {

std::string baseUrl_;
std::string awsAccessKeyId_;  // AWS access key ID
std::string awsSecretKey_;    // AWS secret access key
std::string awsRegion_;       // AWS region

std::string buildAuthRequestBody(const std::string& passcode,
    const std::string& username,
    const MCUConnectionTypes& connectionType,
    const std::string& connectionId)
{
    // ... existing code ...
}

PString dateTimeStamp = PTime().AsString("yyyyMMddTHHmmssZ");
std::string canonicalRequest = "POST" + "\n" +
    "/anonymous_sessions\n" +
    "\n" +
    "content-type:application/json\n" +
    "host:" + host + "\n" +
    "x-amz-date:" + dateTimeStamp + "\n" +
    "\n" +
    "content-type;host;x-amz-date\n" +
    //Aws::Utils::HashingUtils::HexEncode(Aws::Utils::HashingUtils::CalculateSHA256(body);
    PString::StringToHex(PSHA256::Encode(body)).ToLower();

std::string generateSigV4Signature(const std::string& canonicalRequest, const std::string& dateTimeStamp)
{
    std::string kSecret = "AWS4" + awsSecretKey_;
    std::string kDate = PTime().AsString("yyyyMMdd");
    std::string kRegion = awsRegion_;
    std::string kService = "execute-api";
    std::string kSigning = "aws4_request";

    std::string hashAlgorithm = "AWS4-HMAC-SHA256";
    std::string stringToSign = hashAlgorithm + "\n" + dateTimeStamp + "\n" + kDate + "/" + kRegion + "/" + kService + "/" + kSigning + "\n" + PString::StringToHex(PSHA256::Encode(canonicalRequest)).ToLower();

    PSHA256 hmacSha256;
    hmacSha256.SetKey((const BYTE*)(kSecret + kDate).c_str(), (DWORD)(kSecret + kDate).length());
    hmacSha256.Update((const BYTE*)kRegion.c_str(), (DWORD)kRegion.length());
    hmacSha256.Update((const BYTE*)kService.c_str(), (DWORD)kService.length());
    hmacSha256.Update((const BYTE*)kSigning.c_str(), (DWORD)kSigning.length());
    hmacSha256.Update((const BYTE*)stringToSign.c_str(), (DWORD)stringToSign.length());
    std::string signature = PString::StringToHex(hmacSha256.Final()).ToLower();

    return signature;
}

CCPClient::Status CCPClient::AuthenticateViaPasscode(const std::string& passcode,
    const std::string& username,
    const MCUConnectionTypes& connectionType,
    const std::string& connectionId,
    CCPAuthResponse& authResponse)
{
    std::string url = baseUrl_ + "/anonymous_sessions";
    std::string body = buildAuthRequestBody(passcode, username, connectionType, connectionId);
    PTRACE(PTrace::Level::Info, "CCPClient\tAuthenticateViaPasscode");

    PString dateTimeStamp = PTime().AsString("yyyyMMddTHHmmssZ");

    std::string canonicalRequest = "POST\n";
    canonicalRequest += "/anonymous_sessions\n";
    canonicalRequest += "\n";
    canonicalRequest += "content-type:application/json\n";
    canonicalRequest += "host:" + url + "\n";
    canonicalRequest += "x-amz-date:" + dateTimeStamp + "\n";
    canonicalRequest += "x-amz-security-token:" + awsSecurityToken + "\n";
    canonicalRequest += "x-amz-target:<your-api-gateway-target>\n";
    canonicalRequest += "\n";
    canonicalRequest += "content-type;host;x-amz-date;x-amz-security-token;x-amz-target\n";
    canonicalRequest += PString::StringToHex(PSHA256::Encode(body)).ToLower();

    std::string signature = generateSigV4Signature(canonicalRequest, dateTimeStamp);

    PHTTPClient http;
    http.SetProxy(proxy);

    PHTTPRequest req;
    req.SetMethod("POST");
    req.SetURI(url);
    req.SetEntity(body);
    req.SetContentType("application/json");

    std::string authorizationHeader = "AWS4-HMAC-SHA256 Credential=" + awsAccessKeyId_ + "/" + PTime().AsString("yyyyMMdd") + "/" + awsRegion_ + "/execute-api/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=" + signature;
    req.SetHeader("Authorization", authorizationHeader);
    req.SetHeader("Content-Type", "application/json");
    req.SetHeader("Host", url);
    req.SetHeader("x-amz-date", dateTimeStamp);
    req.SetHeader("x-amz-security-token", awsSecurityToken);
    req.SetHeader("x-amz-target", "<your-api-gateway-target>");

    PHTTPResponse resp;
    if (!http.Post(resp, req)) {
        // Handle request failure
        return CCPClient::ERR_RESP;
    }

    // Process the response
    // ...

    return ccpStatus;
}
