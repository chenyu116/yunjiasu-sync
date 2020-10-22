package config

import (
	"github.com/spf13/viper"
	"log"
	"time"
)

var c Config

func init() {
	viper.SetConfigType("yaml")
	viper.SetConfigName("config")
	viper.AddConfigPath("/app")
	viper.AddConfigPath(".")
	ReadConfig()
}

func GetConfig() Config {
	return c
}

func GetCommonConfig() CommonConfig {
	return c.Common
}

func Get(key string) interface{} {
	return viper.Get(key)
}

func GetBool(key string) bool {
	return viper.GetBool(key)
}

func GetInt(key string) int {
	return viper.GetInt(key)
}

func GetString(key string) string {
	return viper.GetString(key)
}

func GetStringMapString(key string) map[string]string {
	return viper.GetStringMapString(key)
}
func GetStringSlice(key string) []string {
	return viper.GetStringSlice(key)
}

func IsSet(key string) bool {
	return viper.IsSet(key)
}

func Set(key string, value interface{}) {
	viper.Set(key, value)
}

type CommonConfig struct {
	BaseURL         string        `mapstructure:"baseURL"`
	SignatureMethod string        `mapstructure:"signatureMethod"`
	CheckInterval   time.Duration `mapstructure:"checkInterval"`
	SyncRetryTimes  int           `mapstructure:"syncRetryTimes"`
}

type CertConfig struct {
	Domain           string        `mapstructure:"domain"`
	TlsName          string        `mapstructure:"tlsName"`
	TlsNamespace     string        `mapstructure:"tlsNamespace"`
	SyncToNamespaces []string      `mapstructure:"syncToNamespaces"`
	CheckInterval    time.Duration `mapstructure:"checkInterval"`
}

type LogConfig struct {
	MaxSize    int  `mapstructure:"maxSize"`
	MaxBackups int  `mapstructure:"maxBackups"`
	MaxAge     int  `mapstructure:"maxAge"`
	Compress   bool `mapstructure:"compress"`
	LocalTime  bool `mapstructure:"localTime"`
}

type Config struct {
	Certs  []CertConfig `mapstructure:"certs"`
	Log    LogConfig    `mapstructure:"log"`
	Common CommonConfig `mapstructure:"common"`
}

func SetConfigPath(path string) {
	viper.SetConfigFile(path)
}

func ReadConfig() {
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}

	err = viper.Unmarshal(&c)
	if err != nil {
		log.Fatal(err)
	}
}
