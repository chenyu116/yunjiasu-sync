package yunjiasu

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/chenyu116/yunjiasu-sync/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
	"time"
)

const (
	deployPending = iota
	deployUploaded
	deployDeployed
	deployDeleted
	deployRenamed

	syncPending = iota
	syncReadK8s
	syncYunJiaSu
	syncNamespaces
)

type Secret struct {
	TlsName          string
	TlsNamespace     string
	Domain           string
	SyncNamespaces   []string
	SyncedNamespaces map[string]struct{}
	Timer            *time.Timer
	CheckInterval    time.Duration
	NotAfter         time.Time
	Cert             *bytes.Buffer
	Key              *bytes.Buffer
	k8sClientset     *kubernetes.Clientset
	deployStatus     int
	syncStatus       int
}

func isNotFound(err error) bool {
	return strings.Index(err.Error(), "not found") > -1
}

func (s *Secret) syncNamespaces() error {
	for _, ns := range s.SyncNamespaces {
		if ns == s.TlsNamespace {
			continue
		}
		if _, ok := s.SyncedNamespaces[ns]; ok {
			continue
		}
		cert, err := s.k8sClientset.CoreV1().Secrets(ns).Get(context.Background(), s.TlsName, metav1.GetOptions{})
		if err != nil {
			if isNotFound(err) {
				newCert := &v1.Secret{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Secret",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      s.TlsName,
						Namespace: ns,
					},
					Data: make(map[string][]byte),
					Type: "kubernetes.io/tls",
				}
				newCert.Data["ca.crt"] = []byte("")
				newCert.Data["tls.crt"] = s.Cert.Bytes()
				newCert.Data["tls.key"] = s.Key.Bytes()
				_, err = s.k8sClientset.CoreV1().Secrets(ns).Create(context.Background(), newCert, metav1.CreateOptions{})
				if err != nil {
					logger.Zap.Error("[syncNamespaces] Create", zap.String("to namespace", ns), zap.String("tlsName", s.TlsName), zap.Error(err))
					return err
				}
			} else {
				logger.Zap.Error("[syncNamespaces]", zap.String("to namespace", ns), zap.String("tlsName", s.TlsName), zap.Error(err))
				return err
			}
		} else {
			updateCert := false
			certDERBlock, _ := pem.Decode(cert.Data["tls.crt"])
			if certDERBlock == nil {
				logger.Zap.Error("[syncNamespaces] certDERBlock is nil", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}))
				updateCert = true
			} else {
				x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
				if err != nil {
					logger.Zap.Error("[syncNamespaces] x509.ParseCertificate", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
					updateCert = true
				}
				if err == nil {
					if x509Cert.NotAfter.Before(s.NotAfter) {
						updateCert = true
					}
				}
			}

			if updateCert {
				logger.Zap.Info("[syncNamespaces] UpdateCert")
				cert.Data["ca.crt"] = []byte("")
				cert.Data["tls.crt"] = s.Cert.Bytes()
				cert.Data["tls.key"] = s.Key.Bytes()
				_, err = s.k8sClientset.CoreV1().Secrets(ns).Update(context.Background(), cert, metav1.UpdateOptions{})
				if err != nil {
					logger.Zap.Error("[syncNamespaces] Create", zap.String("to namespace", ns), zap.String("tlsName", s.TlsName), zap.Error(err))
					return err
				}
			}
		}
		s.SyncedNamespaces[ns] = struct{}{}
	}
	return nil
}

func (s *Secret) syncYunjiasu() (redeploy bool, err error) {
	paramMap := map[string]string{
		"domain": s.Domain,
	}

	headersMap := getRequestHeader(PATH, paramMap)

	body, err := request("GET", PATH+"?domain="+s.Domain, paramMap, headersMap)
	if err != nil {
		logger.Zap.Error("[syncYunjiasu] request", zap.String("domain", s.Domain), zap.Error(err))
		return false, err
	}

	var resp yunjiasuResponse
	err = json.Unmarshal(body, &resp)
	if err != nil {
		logger.Zap.Error("[syncYunjiasu] request", zap.String("domain", s.Domain), zap.Error(err))
		return false, err
	}

	var certResp yunjiasuResponse_result_custom_certificates

	if resp.Success {
		err = json.Unmarshal(body, &certResp)
		if err != nil {
			logger.Zap.Error("[syncYunjiasu]", zap.String("domain", s.Domain), zap.Error(err))
			return false, err
		}
	} else {
		logger.Zap.Error("[syncYunjiasu]", zap.String("domain", s.Domain), zap.ByteString("body", body))
		return false, status.Error(codes.Internal, codes.Internal.String())
	}
	for _, cert := range certResp.Result {
		if cert.Info != s.TlsName {
			continue
		}
		expireOn, err := time.Parse(time.RFC3339, cert.ExpiresOn)
		if err != nil {
			logger.Zap.Error("[syncYunjiasu]", zap.String("domain", s.Domain), zap.Any("cert", cert), zap.Error(err))
			return true, nil
		}
		if expireOn.Before(s.NotAfter) {
			return true, nil
		}
		return false, nil
	}
	return true, nil
}

func (s *Secret) readFromK8s() error {
	secret, err := s.k8sClientset.CoreV1().Secrets(s.TlsNamespace).Get(context.Background(), s.TlsName, metav1.GetOptions{})
	if err != nil {
		logger.Zap.Error("[readCert]", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
		return status.Error(codes.Internal, err.Error())
	}
	certDERBlock, _ := pem.Decode(secret.Data["tls.crt"])
	if certDERBlock == nil {
		logger.Zap.Error("[readCert] certDERBlock is nil", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}))
		return status.Error(codes.Internal, "certDERBlock is nil")
	}
	x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		logger.Zap.Error("[readCert] x509.ParseCertificate", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
		return status.Error(codes.Internal, err.Error())
	}
	s.Cert.Write(secret.Data["tls.crt"])
	s.Key.Write(secret.Data["tls.key"])
	s.NotAfter = x509Cert.NotAfter
	return nil
}

func (s *Secret) deploy() (err error) {
	if s.deployStatus < deployUploaded {
		err = uploadYunjiasuCert(s)
		if err != nil {
			logger.Zap.Error("[deploy] uploadYunjiasuCert", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
			return
		}
		logger.Zap.Info("[deploy] uploadYunjiasuCert OK", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}))
		s.deployStatus = deployUploaded
	}
	if s.deployStatus < deployDeployed {
		err = deployYunjiasuCert(s.Domain, s.TlsName)
		if err != nil {
			logger.Zap.Error("[deploy] deployYunjiasuCert", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
			return
		}
		logger.Zap.Info("[deploy] deployYunjiasuCert OK", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}))
		s.deployStatus = deployDeployed
	}
	if s.deployStatus < deployDeleted {
		err = deleteYunjiasuCert(s.Domain, s.TlsName)
		if err != nil {
			logger.Zap.Error("[deploy] deleteYunjiasuCert", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
			return
		}
		logger.Zap.Info("[deploy] deleteYunjiasuCert OK", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}))
		s.deployStatus = deployDeployed
	}
	if s.deployStatus < deployRenamed {
		err = renameYunjiasuCert(s.Domain, s.TlsName)
		if err != nil {
			logger.Zap.Error("[deploy] renameYunjiasuCert", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
			return
		}
		logger.Zap.Info("[deploy] renameYunjiasuCert OK", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}))
		s.deployStatus = deployRenamed
	}
	return nil
}

func (s *Secret) reset() {
	s.Cert.Reset()
	s.Key.Reset()
	s.SyncedNamespaces = make(map[string]struct{})
	s.deployStatus = deployPending
	s.syncStatus = syncPending
}
func (s *Secret) Sync() {
	var reDeploy bool
	var err error
	retryAfter := time.Second * 10
	retryAfterString := fmt.Sprintf("%+v", retryAfter)
	for {
		select {
		case <-s.Timer.C:
			logger.Zap.Info("[Sync] Start", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}))
			if s.syncStatus < syncReadK8s {
				err = s.readFromK8s()
				if err != nil {
					logger.Zap.Error("[Sync] readFromK8s", zap.String("after", retryAfterString), zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
					s.Timer.Reset(retryAfter)
					continue
				}
				s.syncStatus = syncReadK8s
			}
			if s.syncStatus < syncYunJiaSu {
				reDeploy, err = s.syncYunjiasu()
				if err != nil {
					logger.Zap.Error("[Sync] syncYunjiasu", zap.String("after", retryAfterString), zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
					s.Timer.Reset(retryAfter)
					continue
				}
				s.syncStatus = syncYunJiaSu
			}
			if reDeploy {
				err = s.deploy()
				if err != nil {
					logger.Zap.Error("[Sync] deploy", zap.String("after", retryAfterString), zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
					s.Timer.Reset(retryAfter)
					continue
				}
				reDeploy = false
			}
			if s.syncStatus < syncNamespaces {
				err = s.syncNamespaces()
				if err != nil {
					logger.Zap.Error("[Sync] syncNamespaces", zap.String("after", retryAfterString), zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.Error(err))
					s.Timer.Reset(retryAfter)
					continue
				}
				s.syncStatus = syncNamespaces
			}

			s.reset()
			logger.Zap.Info("[Sync] OK", zap.Strings("secret", []string{s.TlsName, s.TlsNamespace, s.Domain}), zap.String("next check after", fmt.Sprintf("%+v", s.CheckInterval)))
			s.Timer.Reset(s.CheckInterval)
		}
	}
}
