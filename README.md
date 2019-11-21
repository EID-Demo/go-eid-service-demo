# 商米身份证云服务应用服务器 Demo （golang 版本）

## 说明

此项目是商米身份证云服务的应用服务器 Demo。完成以下功能：

- 身份证云解码

### 身份证云解码

接收 Android 端生成的 request_id （参考商米身份证服务 Android 端 SDK），组装、签名参数，
访问商米身份证云服务 openAPI 云解码接口，并解密身份证信息，返回给 Android 端。