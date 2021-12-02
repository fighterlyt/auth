package main

import (
	"auth/session"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/golang-jwt/jwt"

	"gitlab.com/nova_dubai/common/model/invoke"

	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"

	"gitlab.com/nova_dubai/common/twofactor"

	"github.com/fsnotify/fsnotify"

	oauth2err "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

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

	engine := gin.New()
	engine.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type"},
		AllowCredentials: true,
		AllowWildcard:    true,
		MaxAge:           12 * time.Hour,
	}))

	data, err := NewData(mysqlConfig, 1)
	if err != nil {
		panic(err)
	}

	manager := manage.NewDefaultManager()
	manager.MapTokenStorage(data)
	manager.MapClientStorage(data)
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("auth", []byte("auth_jwt"), jwt.SigningMethodHS256))

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *oauth2err.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *oauth2err.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	engine.GET("/authorize", func(ctx *gin.Context) {
		if err := srv.HandleAuthorizeRequest(ctx.Writer, ctx.Request); err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}
	})

	engine.POST("/token", func(ctx *gin.Context) {
		if err := srv.HandleTokenRequest(ctx.Writer, ctx.Request); err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}
	})

	engine.POST("/list", func(ctx *gin.Context) {
		infos, err := data.GetAllClient(ctx)
		if err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		invoke.ReturnSuccess(ctx, infos)
	})

	engine.POST("/info", func(ctx *gin.Context) {

		token, err := srv.ValidationBearerToken(ctx.Request)
		if err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		info := Info{
			UserID:       token.GetUserID(),
			ExpireSecond: int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
		}

		invoke.ReturnSuccess(ctx, info)
	})

	engine.POST("/qrCode", func(ctx *gin.Context) {
		v := new(Users)

		returned, err := invoke.ProcessArgument(ctx, v)
		if returned {
			return
		}

		if err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		user, err := data.GetUser(ctx, v.Username, v.Password)
		if err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		if !user.ShowGoogleQrcode {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, "未开启展示谷歌二维码")
			return
		}
		auth, err := twofactor.NewAuth(user.GoogleAuth)
		if err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		qrcode, _, err := auth.QR("auth")
		if err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		invoke.ReturnSuccess(ctx, qrcode)

	})

	engine.POST("/login", func(ctx *gin.Context) {
		v := new(Users)

		returned, err := invoke.ProcessArgument(ctx, v)
		if returned {
			return
		}

		if err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		_, err = data.GetUser(ctx, v.Username, v.Password)
		if err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		// todo  测试屏蔽谷歌验证码
		//auth, err := twofactor.NewAuth(user.GoogleAuth)
		//if err != nil {
		//	invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
		//	return
		//}
		//
		//ok, err := auth.Validate(v.GoogleCode)
		//if err != nil {
		//	invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
		//	return
		//}
		//
		//if !ok {
		//	invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, "谷歌验证码错误")
		//	return
		//}

		if err := session.SaveUserSession(ctx.Request, ctx.Writer, v.Username); err != nil {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, err.Error())
			return
		}

		http.Redirect(ctx.Writer, ctx.Request, viper.GetString("http.host")+port+"/authorize?"+ctx.Request.URL.RawQuery, http.StatusFound)
		return

	})

	s := &http.Server{
		Addr:    port,
		Handler: engine,
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
	Username         string `gorm:"column:username;primaryKey;type:varchar(255)" json:"username"`
	Password         string `gorm:"column:password;type:varchar(255)" json:"password"`
	GoogleAuth       string `gorm:"column:google_auth;type:varchar(255);comment:谷歌验证至少28位" json:"-"`
	ShowGoogleQrcode bool   `gorm:"column:show_google_qrcode;type:varchar(255);comment:0不展示;1展示" json:"-"`
	GoogleCode       string `gorm:"-" json:"google_code"`
}

func (u Users) Validate() error {
	if u.Username == "" {
		return errors.New("用户名不能为空")
	}
	if u.Password == "" {
		return errors.New("密码不能为空")
	}

	return nil
}

func userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	if userID = session.GetUserSession(r); userID == "" {
		w.Header().Set("Location", "/web/login?"+r.URL.RawQuery)
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
