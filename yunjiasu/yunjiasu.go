package yunjiasu

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"github.com/chenyu116/yunjiasu-sync/config"
	"github.com/chenyu116/yunjiasu-sync/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	accessKey string
	secretKey string
)

func init() {
	accessKey = os.Getenv("ACCESS_KEY")
	secretKey = os.Getenv("SECRET_KEY")
	if accessKey == "" {
		logger.Zap.Fatal("need ENV ACCESS_KEY")
	}
	if secretKey == "" {
		logger.Zap.Fatal("need ENV SECRET_KEY")
	}
}

// 签名算法
const (
	OPENAPI_BASE_URL string = "https://api.su.baidu.com/"
	PATH             string = "v3/yjs/custom_certificates"
)

type yunjiasuResponse_result_custom_certificate struct {
	Info         string   `json:"info"`
	Hosts        []string `json:"hosts"`
	HostsContent string   `json:"hosts_content"`
	Issuer       string   `json:"issuer"`
	ExpiresOn    string   `json:"expires_on"`
	Switch       int      `json:"switch"`
	Id           string   `json:"id"`
}
type yunjiasuResponse_result_custom_certificates struct {
	Result []yunjiasuResponse_result_custom_certificate `json:"result"`
}

type yunjiasuError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type yunjiasuResponse struct {
	Success bool            `json:"success"`
	Errors  []yunjiasuError `json:"errors,omitempty"`
}

func Run() {
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		logger.Zap.Fatal(err.Error())
	}
	clientSet, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		logger.Zap.Fatal(err.Error())
	}
	cf := config.GetConfig()
	for _, v := range cf.Certs {
		s := &Secret{
			TlsName:          v.TlsName,
			TlsNamespace:     v.TlsNamespace,
			Domain:           v.Domain,
			SyncNamespaces:   v.SyncToNamespaces,
			SyncedNamespaces: make(map[string]struct{}),
			Timer:            time.NewTimer(0),
			CheckInterval:    v.CheckInterval * time.Second,
			deployStatus:     deployPending,
			Cert:             new(bytes.Buffer),
			Key:              new(bytes.Buffer),
			k8sClientset:     clientSet,
		}
		go s.Sync()
	}
	select {}
}

func getInitedCommonParamsMap(authPathInfo string) map[string]string {
	cf := config.GetConfig()
	authTimestamp := strconv.FormatInt(time.Now().Unix(), 10)
	paramMap := map[string]string{
		"X-Auth-Access-Key":       accessKey,
		"X-Auth-Nonce":            authTimestamp,
		"X-Auth-Path-Info":        authPathInfo,
		"X-Auth-Signature-Method": cf.Common.SignatureMethod,
		"X-Auth-Timestamp":        authTimestamp,
	}

	return paramMap
}

//排序并拼接参数
func getParsedAllParams(paramMap map[string]string) string {
	var paramList []string

	for k, v := range paramMap {
		var buffer bytes.Buffer
		buffer.WriteString(k)
		buffer.WriteString("=")
		buffer.WriteString(v)

		paramList = append(paramList, buffer.String())
	}

	sort.Strings(paramList)

	return strings.Join(paramList, "&")
}

//获取请求的header
func getRequestHeader(path string, bizParamsMap map[string]string) map[string]string {
	commonParamsMap := getInitedCommonParamsMap(path)
	allParamsMap := make(map[string]string)
	headersMap := make(map[string]string)

	for k, v := range commonParamsMap {
		headersMap[k] = v
	}

	for k, v := range commonParamsMap {
		allParamsMap[k] = v
	}

	for k, v := range bizParamsMap {
		allParamsMap[k] = v
	}

	allParamsStr := getParsedAllParams(allParamsMap)

	sign := getSignature(secretKey, allParamsStr)

	headersMap["X-Auth-Sign"] = sign

	return headersMap
}

//发送http请求
func request(method string, path string, bizParamsMap map[string]string,
	headers map[string]string) ([]byte, error) {
	url := OPENAPI_BASE_URL + path

	params, err := json.Marshal(bizParamsMap)
	if err != nil {
		return nil, err
	}

	payload := strings.NewReader(string(params))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, payload)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func getSignature(secKey string, text string) string {
	key := []byte(secKey)
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(text))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
func deleteYunjiasuCert(domain, tlsName string) error {
	paramMap := map[string]string{
		"domain": domain,
		"info":   tlsName,
	}
	headersMap := getRequestHeader(PATH, paramMap)
	body, err := request("DELETE", PATH, paramMap, headersMap)
	if err != nil {
		return err
	}
	var resp yunjiasuResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return err
	}
	if !resp.Success {
		errString := codes.Unknown.String()
		if len(resp.Errors) > 0 {
			errString = resp.Errors[0].Message
		}
		return status.Error(codes.Unknown, errString)
	}
	return nil
}
func renameYunjiasuCert(domain, tlsName string) error {
	paramMap := map[string]string{
		"domain":   domain,
		"info":     tlsName + "_temp",
		"new_info": tlsName,
		"switch":   "1",
	}
	headersMap := getRequestHeader(PATH, paramMap)
	body, err := request("PATCH", PATH, paramMap, headersMap)
	if err != nil {
		return err
	}
	var resp yunjiasuResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return err
	}
	if !resp.Success {
		errString := codes.Unknown.String()
		if len(resp.Errors) > 0 {
			errString = resp.Errors[0].Message
		}
		return status.Error(codes.Unknown, errString)
	}
	return nil
}
func deployYunjiasuCert(domain, tlsName string) error {
	paramMap := map[string]string{
		"domain":   domain,
		"info":     tlsName + "_upload",
		"new_info": tlsName + "_temp",
		"switch":   "1",
	}
	headersMap := getRequestHeader(PATH, paramMap)
	body, err := request("PATCH", PATH, paramMap, headersMap)
	if err != nil {
		return err
	}
	var resp yunjiasuResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return err
	}
	if !resp.Success {
		errString := codes.Unknown.String()
		if len(resp.Errors) > 0 {
			errString = resp.Errors[0].Message
		}
		return status.Error(codes.Unknown, errString)
	}
	return nil
}
func uploadYunjiasuCert(secret *Secret) error {
	paramMap := map[string]string{
		"domain":      secret.Domain,
		"info":        secret.TlsName + "_upload",
		"certificate": secret.Cert.String(),
		"private_key": secret.Key.String(),
	}
	headersMap := getRequestHeader(PATH, paramMap)
	body, err := request("POST", PATH, paramMap, headersMap)
	if err != nil {
		return err
	}
	var resp yunjiasuResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return err
	}
	if !resp.Success {
		errString := codes.Unknown.String()
		if len(resp.Errors) > 0 {
			errString = resp.Errors[0].Message
		}
		return status.Error(codes.Unknown, errString)
	}
	return nil
}
