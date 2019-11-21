package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"
)

func main() {
	// 读取配置文件
	viper.SetConfigFile("config.toml")
	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}
	http.HandleFunc(viper.GetString("router"), Decode)
	all := viper.AllSettings()
	for key, value := range all {
		fmt.Printf("%s = %s\n", key, value)
	}
	fmt.Println("服务启动...")
	// 启动服务
	err := http.ListenAndServe(viper.GetString("port"), nil)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func Decode(w http.ResponseWriter, r *http.Request) {
	fmt.Println("\n\n------------------------------------------")
	requestID := r.PostFormValue("request_id")
	if requestID == "" {
		_, _ = w.Write([]byte("no request id"))
		return
	}
	fmt.Printf("收到请求[request_id: %s]\n", requestID)

	// 组装请求参数
	data := url.Values{}
	factor := RandString(8)
	data.Add("app_id", viper.GetString("app_id"))
	data.Add("request_id", requestID)
	data.Add("encrypt_factor", factor)

	// 签名
	// 1. 对 key 进行排序
	keys := make([]string, 0)
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	// 2. 组装待签名字符串
	preSign := ""
	for _, key := range keys {
		preSign += fmt.Sprintf("%s=%s&", key, data[key][0])
	}
	preSign = preSign[:len(preSign)-1] + viper.GetString("app_key")
	fmt.Printf("待签名字符串[%s]\n", preSign)
	// 3. 计算签名
	m := md5.New()
	m.Write([]byte(preSign))
	sign := hex.EncodeToString(m.Sum(nil))
	sign = strings.ToUpper(sign)
	data.Add("sign", sign)

	// 请求云解码 openAPI
	info, err := RequestDecode(data)
	if err != nil {
		fmt.Printf("请求失败[%s]\n", err)
	}

	fmt.Println("返回参数:")
	for key, value := range info {
		fmt.Printf("%s = %+v\n", key, value)
	}
	if info["code"] != "10000" {
		fmt.Printf("openapi返回失败[code = %s][msg = %s]\n", info["code"], info["msg"])
		w.Write([]byte("failed"))
		return
	}

	subData := info["data"].(map[string]interface{})
	if _, has := subData["sub_code"]; has {
		fmt.Printf("业务返回失败[code = %s][msg = %s]\n", subData["sub_code"], subData["sub_msg"])
		w.Write([]byte("failed"))
		return
	}

	infoData := subData["info"].(string)

	// 解码身份证信息
	temp, err := base64.StdEncoding.DecodeString(infoData)
	infoStr, err := DesDecryptECB(string(temp), factor)
	if err != nil {
		fmt.Printf("身份证信息解密失败[error = %s]\n", err)
		w.Write([]byte("failed"))
		return
	}
	fmt.Printf("解密成功：%s", infoStr)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(infoStr))
}

func RequestDecode(data url.Values) (map[string]interface{}, error) {
	info := make(map[string]interface{})
	fmt.Println("请求参数:")
	for key, value := range data {
		fmt.Printf("%s = %s\n", key, value[0])
	}

	// 请求 openapi 接口
	resp, err := http.PostForm(viper.GetString("server"), data)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()

	// 读取返回数据
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}

	// 解析返回数据
	err = json.Unmarshal(respData, &info)
	if err != nil {
		fmt.Printf("返回数据解析失败：%s\n", err)
		return info, err
	}
	return info, nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// 生成 n 位随机字符串
func RandString(n int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	b := make([]byte, n)
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

// des 解码
func DesDecryptECB(msg string, key string) (string, error) {
	crypted := []byte(msg)
	block, err := des.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte(key))
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return string(origData), nil
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
