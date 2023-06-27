// 计算HMAC-SHA256签名 
std::string sign(const std::string& key, const std::string& data) { 
	unsigned char* digest = HMAC(EVP_sha256(), key.c_str(), key.size(), reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), nullptr, nullptr); std::stringstream ss; 
	for (int i = 0; i < EVP_MD_size(EVP_sha256()); ++i) { 
		ss << std::hex << static_cast<int>(digest[i]); 
	} 
	return ss.str();
} 

// 添加SIGV4头 
void add_sigv4_header(CURL* curl, const std::string& access_key_id, const std::string& secret_access_key, const std::string& region, const std::string& service, const std::string& method, const std::string& endpoint, const std::string& path, const std::string& query_params, const std::string& payload) { 
	// 构造时间戳和日期 
	time_t now = time(nullptr); 
	struct tm gm_time; 
	gmtime_r(&now, &gm_time); 
	char date[9], datetime[17]; 
	strftime(date, sizeof(date), "%Y%m%d", &gm_time); 
	strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%SZ", &gm_time); 
	// 构造规范请求 
	std::ostringstream oss; 
	oss << method << "\n" << path << "\n" << query_params << "\n" << "host:" << endpoint << "\n" << "x-amz-content-sha256:" << sign("AWS4" + secret_access_key, payload) << "\n" << "x-amz-date:" << datetime << "\n\n" << "host;x-amz-content-sha256;x-amz-date\n" << sign("AWS4" + secret_access_key, ""); 
	std::string canonical_request = oss.str(); 
	// 构造待签名字符串 
	std::ostringstream oss2; oss2 << "AWS4-HMAC-SHA256\n" << datetime << "\n" << date << "/" << region << "/" << service << "/aws4_request\n" << sign("AWS4" + secret_access_key, date) << "\n" << canonical_request; 
	std::string string_to_sign = oss2.str(); 
	// 计算签名 
	std::string signature = sign(sign(sign(sign("AWS4" + secret_access_key, date), region), service), "aws4_request" + string_to_sign); 
	// 添加Authorization头 
	std::ostringstream oss3; 
	oss3 << "AWS4-HMAC-SHA256 Credential=" << access_key_id << "/" << date << "/" << region << "/" << service << "/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date," << " Signature=" << signature; std::string authorization_header = oss3.str(); // 设置HTTP头 struct curl_slist* headers = nullptr; headers = curl_slist_append(headers, ("Authorization: " + authorization_header).c_str()); headers = curl_slist_append(headers, ("X-Amz-Content-Sha256: " + sign("AWS4" + secret_access_key, payload)).c_str()); headers = curl_slist_append(headers, ("X-Amz-Date: " + std::string(datetime)).c_str()); curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
} 

// 替换成自己的访问密钥ID和秘钥 
std::string access_key_id = "AKIA************"; 
std::string secret_access_key = "**************************"; 
// AWS S3的服务名、区域和桶名 
std::string service = "s3"; 
std::string region = "us-west-2"; 
std::string bucket_name = "my-bucket"; 
// 要上传的文件内容 
std::string payload = "Hello, world!"; 
// 计算Content-MD5 
BIO* bmem = BIO_new(BIO_s_mem()); 
BIO_puts(bmem, payload.c_str()); BIO* hash = BIO_new(BIO_f_md()); 
BIO_set_md(hash, EVP_md5()); hash = BIO_push(hash, bmem); 
unsigned char md[EVP_MAX_MD_SIZE]; 
int md_len = 0; 
while (BIO_read(hash, md, sizeof(md)) > 0) { 
	md_len += sizeof(md); 
} 
std::string content_md5 = reinterpret_cast<const char*>(md); 
// 构造URL和HTTP头 std::ostringstream oss; oss << "https://" << bucket_name << ".s3.amazonaws.com/test.txt"; 
std::string url = oss.str(); 
curl_global_init(CURL_GLOBAL_ALL); 
CURL* curl = curl_easy_init(); 
if (!curl) { 
	throw std::runtime_error("Failed to initialize cURL"); 
} 
struct curl_slist* headers = nullptr; 
headers = curl_slist_append(headers, ("Content-MD5: " + content_md5).c_str()); 
curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); 
curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT"); 
curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L); curl_easy_setopt(curl, CURLOPT_READFUNCTION, &read_data); 
curl_easy_setopt(curl, CURLOPT_READDATA, &payload); 
curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(payload.size())); 
curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); 
// 添加SIGV4头 add_sigv4_header(curl, access_key_id, secret_access_key, region, service, "PUT", bucket_name + ".s3.amazonaws.com", "/test.txt", "", payload); 
// 发送HTTP请求 CURLcode res = curl_easy_perform(curl); 
if (res != CURLE_OK) { 
	throw std::runtime_error(curl_easy_strerror(res)); 
}
