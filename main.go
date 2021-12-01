package main

import (
	"auth/session"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

var jsonContentType = []string{"application/json; charset=utf-8"}

// MysqlConfig 数据库配置
type MysqlConfig struct {
	DB      string        `yaml:"db"`      // 数据库名
	Host    string        `yaml:"host"`    // 地址,空字符串表示不使用
	Port    string        `yaml:"port"`    // 端口
	User    string        `yaml:"user"`    // 账号
	Pass    string        `yaml:"pass"`    // 密码
	MaxIdle int           `yaml:"maxIdle"` // 最大空闲
	MaxOpen int           `yaml:"maxOpen"` // 最大打开
	MaxLife time.Duration `yaml:"maxLife"` // 最大存活时间
}

type HTTPConfig struct {
	Host string `yaml:"host"` // 本机域名
	Port string `yaml:"port"` // 端口
}

func main() {
	if err := Init("", "auth"); err != nil {
		panic(err)
	}

	mysqlConfig := new(MysqlConfig)
	if err := viper.UnmarshalKey("mysql", mysqlConfig, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		panic(err)
	}

	httpConfig := new(HTTPConfig)
	if err := viper.UnmarshalKey("http", httpConfig); err != nil {
		panic(err)
	}

	port := httpConfig.Port
	if len(port) > 0 {
		if port[0] != ':' {
			port = ":" + port
		}
	}

	data, err := NewData(mysqlConfig, 1)
	if err != nil {
		panic(err)
	}
	manager := manage.NewDefaultManager()
	manager.MapTokenStorage(data)
	manager.MapClientStorage(data)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.HandleAuthorizeRequest(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := srv.HandleTokenRequest(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {

		token, err := srv.ValidationBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		info := Info{
			UserID:       token.GetUserID(),
			ExpireSecond: int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
		}
		header := w.Header()
		if val := header["Content-Type"]; len(val) == 0 {
			header["Content-Type"] = jsonContentType
		}

		marshal, err := json.Marshal(info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(marshal)
		return
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {

		v := new(Users)

		if r == nil || r.Body == nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
		}

		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(v); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := data.GetUser(r.Context(), v.Username, v.Password); err == nil {
			if err := session.SaveUserSession(r, w, v.Username); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, viper.GetString("http.host")+port+"/authorize?"+r.URL.RawQuery, http.StatusFound)
			return
		}

		http.Error(w, "you dont have permission to access", http.StatusUnauthorized)
		return
	})
	s := &http.Server{
		Addr:    port,
		Handler: mux,
	}

	// 创建系统信号接收器
	done := make(chan os.Signal)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-done
		if err := s.Shutdown(context.Background()); err != nil {
			log.Fatal("优雅关闭失败", err)
		}
	}()
	log.Printf("已启动 监听地址:%s", s.Addr)
	err = s.ListenAndServe()
	if err != nil {
		if err == http.ErrServerClosed {
			log.Print("应用已经退出了")
		} else {
			log.Fatal("服务器以外关闭")
		}
	}

}

type Users struct {
	Username string `gorm:"column:username;primaryKey;type:varchar(255)" json:"username"`
	Password string `gorm:"column:password;type:varchar(255)" json:"password"`
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	if userID = session.GetUserSession(r); userID == "" {
		w.Header().Set("Location", "/login?"+r.URL.RawQuery)
		w.WriteHeader(302)
	}

	return
}

// Init init config
func Init(confPath string, prefix string) error {
	err := initConfig(confPath, prefix)
	if err != nil {
		return err
	}
	return nil
}

// initConfig init config from conf file
func initConfig(confPath string, prefix string) error {
	if confPath != "" {
		viper.SetConfigFile(confPath) // 如果指定了配置文件，则解析指定的配置文件
	} else {
		viper.AddConfigPath("conf") // 如果没有指定配置文件，则解析默认的配置文件
		viper.SetConfigName("custom")
	}
	viper.SetConfigType("yaml") // 设置配置文件格式为YAML
	viper.AutomaticEnv()        // 读取匹配的环境变量
	viper.SetEnvPrefix(prefix)  // 读取环境变量的前缀
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	if err := viper.ReadInConfig(); err != nil { // viper解析配置文件
		return fmt.Errorf("err: %+v,stack: %s", err, debug.Stack())
	}
	watchConfig()
	if viper.GetString("deploy.env") == "uat" {
		os.Setenv("DEPLOY_ENV", "uat")
	}
	log.Printf("%s 启动, 部署环境: %s", prefix, os.Getenv("DEPLOY_ENV"))

	return nil
}

// 监控配置文件变化并热加载程序
func watchConfig() {
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Printf("Config file changed: %s", e.Name)
	})
}

type Info struct {
	UserID       string `json:"user_id"`
	ExpireSecond int64  `json:"expire_second"`
}
