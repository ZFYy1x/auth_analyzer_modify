# 越权测试插件

## 针对原版auth_analyzer插件做出部分修改

## 版本更新

### V1.5版本修改

1、功能增强
- 看板右键支持发送到 Repeater（批量、多标签“水平越权/垂直越权/未授权”+自定义标签）
- 表格支持 Ctrl/Command 非连续多选
- 搜索前自动重建全文索引，确保新请求可被立即搜索

2、性能优化
- 表格排序/重绘增加防抖，减少大数据量场景下的卡顿
- 保持已有去重/缓存和批量更新策略，提升流畅度

3、稳定性
- 多处 UI 更新切回 EDT，避免因后台线程直接操作 Swing 造成界面卡死或显示异常

### V1.4版本修改

1、修复重复项筛选逻辑bug

- 之前勾选重复项会隐藏重复项，现在修复为勾选显示所有请求

2、性能优化

- 批量UI更新，减少界面卡顿
- 添加缓存机制，提升搜索和过滤速度
- 异步处理差异计算，不再阻塞界面
- 优化重复检测算法，大数据量下性能更好


### V1.3版本修改

1、修复多维去重筛选后删除看板数据bug

2、修复同接口不同参数评论ID编号指向问题

### V1.2版本修改

1、添加汉化

2、添加域名黑白名单功能

3、添加展示筛选完整url

4、添加复制看板中所有url

5、修复原插件Swing UI渲染问题

6、添加多维签名去重优化看板数据

- 启用多维去重后 同接口同参数将在看板显示进行去重，同接口不同参数会在看板展示，并标记评论ID为首条相同接口

<img width="1436" height="690" alt="image" src="https://github.com/user-attachments/assets/c706b891-1562-41bd-af00-f4dc2f13b547" />


<img width="1918" height="926" alt="image" src="https://github.com/user-attachments/assets/7b6a377e-5e8b-4f9e-b7a0-cbd1594db0f4" />

<img width="1915" height="960" alt="image" src="https://github.com/user-attachments/assets/725a2c32-9ad0-4a8e-8b88-dfdbe422bbad" />

源项目插件地址：https://github.com/simioni87/auth_analyzer

# Auth Analyzer
### Table of Contents
- [What is it?](#what-is-it)
- [Why should I use Auth Analyzer?](#why-should-i-use-auth-analyzer)
- [GUI Overview](#gui-overview)
- [Parameter Extraction](#parameter-extraction)
  * [Auto Extract](#auto-extract)
  * [From To String](#from-to-string)
  * [Static Value](#static-value)
  * [Prompt for Input](#prompt-for-input)
- [Parameter Replacement](#parameter-replacement)
  * [Replacement Location](#replacement-location)
- [Parameter removement](#parameter-removement)
- [Sample Usage](#sample-usage)
  * [Auto extract session Cookie](#auto-extract-session-cookie)
  * [Session Header and CSRF Token Parameter](#session-header-and-csrf-token-parameter)
  * [Auto extract from JavaScript variable](#auto-extract-from-javascript-variable)
  * [Auto extract and insert a Bearer Token](#auto-extract-and-insert-a-bearer-token)
  * [Test several roles at a time](#test-several-roles-at-a-time)
  * [Refresh Auto Exracted Parameter Value](#refresh-auto-exracted-parameter-value)
  * [Test idempotent Operations](#test-idempotent-operations)
  * [Test anonymous sessions](#test-anonymous-sessions)
  * [Test CORS configuration](#test-cors-configuration)
  * [Test CSRF Check mechanism](#test-csrf-check-mechanism)
  * [Verify the Bypass Status](#verify-the-bypass-status)
- [Processing Filter](#processing-filter)
- [Bypass Detection](#bypass-detection)
- [Features](#features)


## What is it?
The Burp extension helps you to find authorization bugs. Just navigate through the web application with a high privileged user and let the Auth Analyzer repeat your requests for any defined non-privileged user. With the possibility to define Parameters the Auth Analyzer is able to extract and replace parameter values automatically. With this for instance, CSRF tokens or even whole session characteristics can be auto extracted from responses and replaced in further requests. Each response will be analyzed and tagged on its bypass status. 

## Why should I use Auth Analyzer?
There are other existing Burp Extensions doing basically similar stuff. However, the force of the parameter feature and automatic value extraction is the main reason for choosing Auth Analyzer. With this you don’t have to know the content of the data which must be exchanged. You can easily define your parameters and cookies and Auth Analyzer will catch on the fly the values needed. The Auth Analyzer does not perform any preflight requests. It does basically just the same thing as your web app. With your defined user roles / sessions.

## GUI Overview
(1) Create or Clone a Session for every user you want to test.

(2) Save and load session setup

(3) Specify the session characteristics (Header(s) and / or Parameter(s) to replace)

(4) Set Filters if needed

(5) Start / Stop and Pause Auth Analyzer

(6) Specify table filter

(7) Navigate through Web App with another user and track results of the repeated requests

(8) Export table data to XML or HTML

(9) Manually analyze original and repeated requests / responses 


![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/complete_gui.png)

## Semi Automated Authorization Testing
If you have the resources you want to test in your sitemap, it is very easy and quick to perform your authorization tests. In the very first step define your sessions you want to test. Then just expand your sitemap, select the resources and repeat the requests through the context menu. Additionally you can define some options which requests should be repeated and which not. With this you can perform authorization tests of a complex website within seconds.

## Parameter Extraction
The Auth Analyzer has the possibility to define parameters which are replaced before the request for the given session will be repeated. The value for the given parameter can be set according to different requirements.
### Auto Extract
The parameter value will be extracted if it occurs in a response with one of the following constraints:

* A response with a `Set-Cookie Header` with a Cookie name set to the defined `Extract Field Name`

* An `HTML Document Response` contains an input field with the name attribute set to the defined `Extract Field Name`

* A `JSON Response` contains a key set to the `Extract Field Name`

Per default the Auth Analyzer tries to auto extract the parameter value from all locations. However, clicking on the parameter settings icon lets you restrict the auto extract location according to your needs.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/param_auto_extract_location.png)

### From To String
The parameter will be extracted if the response contains the specified `From String` and `To String` in a line. The From-To String can be set either manually or directly by the corresponding context menu. Just mark the word you want to extract in any response and set as `From-To Extract` for the parameter you like.

Per default the Auth Analyzer tries to extract the value from header and body at most textual responses. However, clicking on the parameter settings icon lets you restrict the From-To extract location according to your needs.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/param_fromto_extract_location.png)

### Static Value
A static parameter value can be defined. This can be used for instance for static CSRF tokens or login credentials.

### Prompt for Input
You will be prompted for input if the defined parameter is present in a request. This can be used for instance to set 2FA codes.

## Parameter Replacement
If a value is set (extracted or defined by the user) it will be replaced if the corresponding parameter is present in a request. The conditions for parameter replacements are:
### Replacement Location
The parameter will be replaced if it is present at one of the following locations:

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/param_replace_locations.png)

* `In Path` (e.g. `/api/user/99/profile` --> if a parameter named `user` is present, the value `99` will be replaced)

* `URL Parameter` (e.g. `email=hans.wurst[a]gmail.com`)

* `Cookie Parameter` (e.g. `PHPSESSID=mb8rkrcdg8765dt91vpum4u21v`)

* `Body Parameter` either `URL-Encoded` or `Multipart Form Data`

* `JSON Parameter` (e.g. `{"email":"hans.wurst[a]gmail.com"}`)

Per default the parameter value will be replaced at each location. However, clicking on the parameter settings icon lets you restrict the location according to your needs.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/param_replace_location.png)


## Parameter removement
The defined parameter can be removed completely for instance to test CSRF check mechanisms. 

## Sample Usage

### Auto extract session Cookie
Define the username and password as a `static value`. The session cookie name must be defined as `auto extract`. Verify that you start navigating through the application with no session cookie set. Login to the web app. The Auth Analyzer will repeat the login request with the static parameters and automatically gets the session by the `Set-Cookie` header. This Cookie will be used for further requests of the given session. The defined Cookie will be treated as a parameter and therefore no Cookie Header must be defined.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/auto_extract_session_id_1.png)

Hint: You can restrict the extract and replace conditions for a parameter to avoid malfunction at the extracting / replacing stage.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/parameter_settings_session_cookie.png)

### Session Header and CSRF Token Parameter
Define a Cookie header and a CSRF token (with `auto value extract`). The CSRF token value will be extracted if it is present in an `HTML Input Tag`, a `Set-Cookie Header` or a `JSON Response` of the given session.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/session_header_with_csrf_token.png)

### Auto extract from JavaScript variable
Since the `Auto Extract` method only works on `HTML Input Fields`, `JSON Objects` or `Set-Cookie Headers` we must use the generic extraction method called `From To String`. With this extraction method we can extract any value from a response if it is located between a unique starting and ending string. The Auth Analyzer provides a context menu method to set the `From String` and `To String` automatically. Just mark the String you want to extract and set as `From-To Extract` by the context menu.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/auto_extract_csrftoken_from_js_var.png)

### Auto extract and insert a Bearer Token
Since the Authorization Header is not treated as a parameter (as it is done with the Cookie Header), we can use a header insertion point to achieve what we want. Just mark and right click the value you want to replace in the specified header. The `defaultvalue` will be used if no parameter value is extracted yet.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/auto_extract_and_insert_bearer_token.png)

### Test several roles at a time
Just create as many sessions as you want to test several roles at a time. 

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/several_sessions_1.png)

### Refresh Auto Exracted Parameter Value
Just press `Renew` on the session status panel or repeat the affected request by the context menu (mouse right click in the table entry). Hint: The login request(s) can be marked and filtered afterwards.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/renew_session.png)

### Test idempotent Operations
Original Requests can be dropped for testing idempotent operations (e.g. a `DELETE` function).

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/idempotent_operations.png)

### Test anonymous sessions
If an anonymous user needs a valid characteristic (e.g., a valid cookie value) you have to define the header as usual. Otherwise, you can define a header to remove as follows:

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/test_anonymous.png)

### Test CORS configuration
You can easily test a large number of endpoints on its individual CORS settings by adding an Origin header at `Header(s) to replace` and select `Test CORS` on the Session Panel. By selecting `Test CORS` the Auth Analyzer will change the HTTP method to `OPTIONS` before the request is repeated

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/test_cors.png)

### Test CSRF Check mechanism
A specified parameter can be removed by selecting the `Remove Checkbox`. This can be used for instance to test the CSRF check mechanism.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/remove_csrf.png)

### Verify the Bypass Status
The Auth Analyzer provides a build in comparison view to verify the differences between two responses. Just mark the message you want to analyze and change the message view `(1)`. You are now able to compare the two requests `(2) (3)`. The built in `Diff` Feature will calculate and show the differences between the two requests in real time `(4)`
![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/compare_view.png)

Expanded Diff view:

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/diff_view.png)

## Processing Filter
The Auth Analyzer should process two types of requests / responses:

* The response contains a value which must be extracted

* The requested resource should not be accessible by the defined session(s)

For instance, we don’t want to process a static JavaScript file because it is accessible for everyone and (hopefully) does not contain any protected data. To achieve this, we can set following types of filters:
*	Only In Scope (only requests to the set Scope will be processed)
*	Only Proxy Traffic (only requests to the "Proxy History" will be processed)
*	Exclude Filetypes (specified Filetypes can be excluded)
*	Exclude HTTP Methods (specified HTTP Methods can be excluded)
*	Exclude Status Codes (specified Status Codes can be excluded)
*	Exclude Paths (specified Paths can be excluded)
*	Exclude Queries / Params (specified Queries / Params can be excluded) 

## Automated Response Analysis
*	The Response will be declared as SAME if `Both Responses have same Response Body` and `same Response Code`
*	The Response will be declared as SIMILAR if `Both Responses have same Response Code` and `Both Responses have +-5% of response body length`
*	The Response will be declared as DIFFERENT in every other case

## Features
*	Session Creation for each user role
*	Renaming and Removing a Session
*	Clone a Session
*	Set any amount of Headers to replace / add
*	Set Headers to remove
*	Set any amount of parameters to replace
*	Define how the parameter value will be discovered (automatic, static, prompt for input, from to string)
*	Remove a specified parameter
*	Detailed Filter Rules
*	Detailed Status Panel for each Session
*	Pause each Session separately
*	Renew Auto Extracted Parameter Value automatically
*	Repeat Request by context menu
*	Table Data Filter
*	Table Data Export Functionality
*	Start / Stop / Pause the "Auth Analyzer"
*	Pause each Session seperatly
*	Restrict session to defined scope
*	Filter Requests with same header(s)
* Drop Original Request functionality
*	Detailed view of all processed Requests and Responses
*	Send Header(s) and / or Parameter(s) directly to Auth Analyzer by Context Menu
*	Auto save current configuration
* Save to file and load from file current configuration
* Search function in repeated requests
* Semi Automated Authoriztaion Testing
