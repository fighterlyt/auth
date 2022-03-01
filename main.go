package main

import (
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

	jwt "github.com/appleboy/gin-jwt/v2"
	"gitlab.com/nova_dubai/auth/model"

	"gitlab.com/nova_dubai/common/model/invoke"

	"github.com/gin-contrib/cors"

	"github.com/gin-gonic/gin"

	"gitlab.com/nova_dubai/common/twofactor"

	"github.com/fsnotify/fsnotify"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

const (
	IdentityKey = "uid"
)

var ErrReturned = errors.New("已经写入响应")

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
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"*"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"*"},
		AllowCredentials: true,
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		MaxAge: 12 * time.Hour,
	}))

	data, err := NewData(mysqlConfig)
	if err != nil {
		panic(err)
	}

	mw, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:   "auth",
		Key:     []byte("auth_jwt"),
		Timeout: time.Hour * 24,
		Authenticator: func(ctx *gin.Context) (interface{}, error) {
			v := new(Users)

			returned, err := invoke.ProcessArgument(ctx, v)
			if returned {
				return nil, ErrReturned
			}

			if err != nil {
				return nil, err
			}

			user, err := data.GetUser(ctx, v.Username, v.Password)
			if err != nil {
				return nil, err
			}

			auth, err := twofactor.NewAuth(user.GoogleAuth)
			if err != nil {
				return nil, err
			}

			ok, err := auth.Validate(v.GoogleCode)
			if err != nil {
				return nil, err
			}

			if !ok {
				return nil, errors.New("谷歌验证码错误")
			}

			return &model.Info{
				UserID: user.Username,
			}, nil
		},
		Authorizator: func(data interface{}, ctx *gin.Context) bool {
			if info, ok := data.(*model.Info); ok {
				return info.UserID != ""
			}

			return false
		},
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*model.Info); ok {
				return jwt.MapClaims{
					IdentityKey: v.UserID,
				}
			}
			return nil
		},
		Unauthorized: func(ctx *gin.Context, code int, message string) {
			invoke.ReturnFail(ctx, invoke.Fail, invoke.ErrFail, message)
			return
		},
		LogoutResponse:  nil,
		RefreshResponse: nil,
		IdentityHandler: func(ctx *gin.Context) interface{} {
			claims := jwt.ExtractClaims(ctx)
			id := claims[IdentityKey].(string)
			return &model.Info{id}
		},
		IdentityKey: IdentityKey,
	})
	if err != nil {
		panic(err)
	}

	engine.POST("/login", mw.LoginHandler)

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

	mw.LoginResponse = func(ctx *gin.Context, code int, token string, expire time.Time) {
		userID, err := ParseToken(mw, token)
		if err == nil {
			clients, err := data.GetClients(ctx, userID)
			if err == nil {
				invoke.ReturnSuccess(ctx, gin.H{
					"infos":  clients,
					"expire": expire,
					"token":  token,
				})
				return
			}

		}

		invoke.ReturnSuccess(ctx, gin.H{
			"infos":  make([]interface{}, 0),
			"expire": expire,
			"token":  token,
		})

	}

	engine.Use(mw.MiddlewareFunc())

	engine.POST("/info", func(ctx *gin.Context) {

		userInfo, exist := ctx.Get(IdentityKey)
		if !exist {
			invoke.ReturnFail(ctx, invoke.Unauthorized, invoke.ErrFail, "")
			return
		}

		info, ok := userInfo.(*model.Info)
		if !ok {
			invoke.ReturnFail(ctx, invoke.Unauthorized, invoke.ErrFail, "")
			return
		}

		user, err := data.GetUserByUsername(ctx, info.UserID)
		if err != nil {
			invoke.ReturnFail(ctx, invoke.Unauthorized, invoke.ErrFail, "")
			return
		}

		if !user.IsAdmin {
			if user.Clients == nil {
				invoke.ReturnFail(ctx, invoke.Unauthorized, invoke.ErrFail, "该用户没有绑定业务方")
				return
			}

			clientIP := ctx.ClientIP()
			// 域名加速
			if forwardIP := ctx.Request.Header.Get(`X-Forwarded-For`); forwardIP != `` {
				ips := strings.Split(forwardIP, `,`)
				clientIP = strings.TrimSpace(ips[0])
			}

			log.Println("来自业务方", clientIP)

			for _, client := range user.Clients {
				if client.IP == clientIP {
					invoke.ReturnSuccess(ctx, model.Info{
						UserID: info.UserID,
					})
					return

				}
			}

			invoke.ReturnFail(ctx, invoke.Unauthorized, invoke.ErrFail, fmt.Sprintf("该用户未匹配业务方"))
			return

		}

		invoke.ReturnSuccess(ctx, model.Info{
			UserID: info.UserID,
		})

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
	Username         string    `gorm:"column:username;primaryKey;type:varchar(255)" json:"username"`
	Password         string    `gorm:"column:password;type:varchar(255)" json:"password"`
	GoogleAuth       string    `gorm:"column:google_auth;type:varchar(255);comment:谷歌验证至少28位" json:"-"`
	ShowGoogleQrcode bool      `gorm:"column:show_google_qrcode;type:varchar(255);comment:0不展示;1展示" json:"-"`
	Clients          []*Client `gorm:"foreignKey:username;references:username" json:"-"`
	IsAdmin          bool      `gorm:"column:is_admin;type:tinyint;default:0;comment:是否为管理员" json:"is_admin"`
	GoogleCode       string    `gorm:"-" json:"google_code"`
}

func ParseToken(mw *jwt.GinJWTMiddleware, tokenStr string) (userID string, err error) {
	token, err := mw.ParseTokenString(tokenStr)
	if err != nil {
		return "", err
	}

	claims := jwt.ExtractClaimsFromToken(token)

	userID, ok := claims[IdentityKey].(string)
	if !ok {

		return "", errors.New("未找到用户ID")
	}

	return userID, nil
}

func (u Users) TableName() string {
	return "oauth2_users"
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
