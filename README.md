# PrivHunterAI   
A tool that detects unauthorized access vulnerabilities through passive proxying, leveraging mainstream AI engines such as Kimi, DeepSeek, GPT, and others. Its core detection capabilities are built upon the open APIs of these AI engines, supporting data transmission and interaction via the HTTPS protocol.

## Workflow
<img src="https://github.com/Ed1s0nZ/PrivHunterAI/blob/main/img/%E6%B5%81%E7%A8%8B%E5%9B%BE.png" width="800px">  


## Instructions for Use
1. Download the source code or Releases;
2. Edit the `config.json` file in the root directory to configure the `AI` and corresponding `apiKeys` (only one configuration is required); (AI values can be set to qianwen, kimi, hunyuan, gpt, glm, or deepseek);
3. Configure `headers2` (headers for Request B); optionally configure `suffixes` and `allowedRespHeaders` (interface suffix whitelist, e.g., .js);
4. Execute `go build` to compile the project, then run the binary file (if you downloaded Releases, you can run the binary file directly);
5. After the first program launch, install the certificate to resolve HTTPS traffic. The certificate is automatically generated upon initial startup and located at ~/.mitmproxy/mitmproxy-ca-cert.pem (Windows path: %USERPROFILE%\\.mitmproxy\mitmproxy-ca-cert.pem). For installation steps, refer to the Python mitmproxy documentation: [About Certificates](https://docs.mitmproxy.org/stable/concepts-certificates/).
6. Configure BurpSuite to use the proxy server `127.0.0.1:9080` (the port can be adjusted in `mitmproxy.go` under `Addr:“:9080”,`) to begin scanning;
7. Scan results can be viewed via both the terminal and web interface. Access the frontend results at `127.0.0.1:8222`.

### 配置文件介绍（config.json）
| 字段             | 用途                                                                                   | 内容举例                                                                                                  |
|------------------|----------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `AI`             | Specify the AI model to use                                                                   | `qianwen`, `kimi`, `hunyuan`, `gpt`, `glm`, or `deepseek`                                                                                              |
| `apiKeys`        | Store API keys for different AI services (enter one matching the AI model)                                                        | - `“kimi”: “sk-xxxxxxx”`<br>- `“deepseek”: “sk-yyyyyyy”`<br>- `“qianwen”: “sk-zzzzzzz”`<br>- `‘hunyuan’: “sk-aaaaaaa”`                 |
| `headers2`       | Custom HTTP request headers for Request B                                                           | - `“Cookie”: “Cookie2”`<br>- `“User-Agent”: ‘PrivHunterAI’`<br>- `“Custom-Header”: “CustomValue”`    |
| `suffixes`       | List of file suffixes to filter                                                     | `.js`, `.ico`, `.png`, `.jpg`, `.jpeg`                                                |
| `allowedRespHeaders` | Content types (`Content-Type`) in HTTP response headers to filter                                       | `image/png`, `text/html`, `application/pdf`, `text/css`, `audio/mpeg`, `audio/wav`, `video/mp4`, `application/grpc`|
| `respBodyBWhiteList` | Authorization keywords (e.g., “No query permission”, “Insufficient permission”) for preliminary screening of non-privileged interfaces | - `Invalid parameters`<br>- `Incorrect page number`<br>- `File does not exist`<br>- `System busy, please try again later`<br>- `Request parameter format incorrect`<br>- `Insufficient permissions`<br>- `Token cannot be empty`<br>- `Internal error`|

## Output Effect
Continuously optimized, the current output results are as follows:

1. Terminal Output:
<img src="https://github.com/Ed1s0nZ/PrivHunterAI/blob/main/img/%E6%95%88%E6%9E%9C.png" width="800px">  

2. Frontend output (access 127.0.0.1:8222):
<img src="https://github.com/Ed1s0nZ/PrivHunterAI/blob/main/img/%E5%89%8D%E7%AB%AF%E7%BB%93%E6%9E%9C.png" width="800px">

## Follow-Up Plan
1. Add scanning for sensitive information, such as detecting leaked keys in JavaScript files through regular expression matching combined with AI-assisted recognition;
2. Optimize the scanning process for privilege escalation vulnerabilities and unauthorized access vulnerabilities to achieve more accurate scans while consuming fewer tokens.

## Update Timeline
- 2025.02.18
  1. ⭐️Added scan failure retry mechanism to prevent missed scans;
  2. ⭐️Added response Content-Type whitelist to exclude static files from scanning;
  3. ⭐️Added limit on maximum bytes per AI request during scans to prevent failures caused by oversized packets.
- 2025.02.25 - 02.27
  1. ⭐️ Added URL analysis (preliminary determination of whether it may be a public interface requiring no data authentication);
  2. ⭐️ Added frontend result display functionality.
  3. ⭐️ Added capability to add additional headers for Request B (supporting scenarios where authentication is not handled via cookies).
- 2025.03.01
  1. Optimize prompts to reduce false positive rates;
  2. Refine retry mechanism: Display prompts like `AI analysis anomaly detected, retrying... Reason: API returned 401: {“code”:“InvalidApiKey”,“message”:“Invalid API-key provided.”,‘request_id’:“xxxxx”}`. Retry every 10 seconds; abandon after 5 consecutive failures (prevent infinite loops).
- 2025.03.03
  1. 💰 Cost optimization: Added authentication keyword filtering (e.g., “No query permission available,” “Insufficient permissions”) before triggering AI privilege violation checks. If keywords match, directly output non-violation results to conserve AI tokens and improve resource efficiency.
- 2025.03.21
  1. ⭐️ Added terminal output of request packet logs.
- 2025.04.10
  1. ⭐️ Added output of result confidence scores and optimized prompts.
- 2025.04.22 - 04.23
  1. Optimized frontend styling and introduced paginated query functionality to avoid loading all data at once, reducing browser rendering load and improving page responsiveness and user experience.
- 2025.06.07
  1. ⭐️ Added “Export Results” feature;
  2. Resolved response body garbled text issue.

# Notice
Disclaimer: For technical exchange purposes only. Do not use for illegal activities.
