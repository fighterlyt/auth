package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"net/url"
	"os"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	_ "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Data .
type Data struct {
	tableName       string
	clientTableName string
	usersTableName  string
	db              *gorm.DB
	stdout          io.Writer
	ticker          *time.Ticker
}

type Client struct {
	ID     string `gorm:"column:id;type:varchar(255)" json:"id"`
	Secret string `gorm:"column:secret;type:varchar(255)" json:"secret"`
	Domain string `gorm:"column:domain;type:varchar(255)" json:"domain"`
	Remark string `gorm:"column:remark;type:varchar(255)" json:"remark"`
	UserID string
}

func (c *Client) GetID() string {
	return c.ID
}

func (c *Client) GetSecret() string {
	return c.Secret
}

func (c *Client) GetDomain() string {
	return c.Domain
}

func (c *Client) GetUserID() string {
	return c.UserID
}

func (d *Data) GetUser(ctx context.Context, username string, password string) (user *Users, err error) {
	user = &Users{}

	if err := d.db.Table(d.usersTableName).Where("username = ? and password = ?", username, password).First(user).Error; err != nil {
		return nil, err
	}

	return user, nil

}

type ClientInfo struct {
	Domain string `gorm:"column:domain;type:varchar(255)" json:"domain"`
	Remark string `gorm:"column:remark;type:varchar(255)" json:"remark"`
}

func (d *Data) GetAllClient(ctx context.Context) ([]*ClientInfo, error) {
	var infos []*ClientInfo

	if err := d.db.Table(d.clientTableName).Select("domain", "remark").Find(&infos).Error; err != nil {
		return nil, err
	}

	return infos, nil
}

func (d *Data) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	client := &Client{}
	if err := d.db.Table(d.clientTableName).Where("id = ?", id).First(client).Error; err != nil {
		return nil, err
	}
	return client, nil
}

func (d *Data) Endpoint() (string, error) {
	return "", nil
}

// SetStdout set error output
func (d *Data) SetStdout(stdout io.Writer) *Data {
	d.stdout = stdout
	return d
}

func (d *Data) Start() error {
	return nil
}

func (d *Data) errorf(format string, args ...interface{}) {
	if d.stdout != nil {
		buf := fmt.Sprintf(format, args...)
		d.stdout.Write([]byte(buf))
	}
}
func (d *Data) gc() {
	for range d.ticker.C {
		now := time.Now().Unix()
		var count int64
		if err := d.db.Table(d.tableName).Where("expired_at <= ?", now).Or("code = ? and access = ? AND refresh = ?", "", "", "").Count(&count).Error; err != nil {
			d.errorf("[ERROR]:%s\n", err)
			return
		}
		if count > 0 {
			// not soft delete.
			if err := d.db.Table(d.tableName).Where("expired_at <= ?", now).Or("code = ? and access = ? AND refresh = ?", "", "", "").Unscoped().Delete(&StoreItem{}).Error; err != nil {
				d.errorf("[ERROR]:%s\n", err)
			}
		}
	}
}

// Create create and store the new token information
func (d *Data) Create(ctx context.Context, info oauth2.TokenInfo) error {
	jv, err := json.Marshal(info)
	if err != nil {
		return err
	}
	item := &StoreItem{
		Data: string(jv),
	}

	if code := info.GetCode(); code != "" {
		item.Code = code
		item.ExpiredAt = info.GetCodeCreateAt().Add(info.GetCodeExpiresIn()).Unix()
	} else {
		item.Access = info.GetAccess()
		item.ExpiredAt = info.GetAccessCreateAt().Add(info.GetAccessExpiresIn()).Unix()

		if refresh := info.GetRefresh(); refresh != "" {
			item.Refresh = info.GetRefresh()
			item.ExpiredAt = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Unix()
		}
	}

	return d.db.WithContext(ctx).Table(d.tableName).Create(item).Error
}

// RemoveByCode delete the authorization code
func (d *Data) RemoveByCode(ctx context.Context, code string) error {
	return d.db.WithContext(ctx).
		Table(d.tableName).
		Where("code = ?", code).
		Update("code", "").
		Error
}

// RemoveByAccess use the access token to delete the token information
func (d *Data) RemoveByAccess(ctx context.Context, access string) error {
	return d.db.WithContext(ctx).
		Table(d.tableName).
		Where("access = ?", access).
		Update("access", "").
		Error
}

// RemoveByRefresh use the refresh token to delete the token information
func (d *Data) RemoveByRefresh(ctx context.Context, refresh string) error {
	return d.db.WithContext(ctx).
		Table(d.tableName).
		Where("refresh = ?", refresh).
		Update("refresh", "").
		Error
}

func (d *Data) toTokenInfo(data string) oauth2.TokenInfo {
	var tm models.Token
	err := json.Unmarshal([]byte(data), &tm)
	if err != nil {
		return nil
	}
	return &tm
}

// GetByCode use the authorization code for token information data
func (d *Data) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	if code == "" {
		return nil, nil
	}

	var item StoreItem
	if err := d.db.WithContext(ctx).
		Table(d.tableName).
		Where("code = ?", code).
		Find(&item).Error; err != nil {
		return nil, err
	}
	if item.ID == 0 {
		return nil, nil
	}

	return d.toTokenInfo(item.Data), nil
}

// GetByAccess use the access token for token information data
func (d *Data) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	if access == "" {
		return nil, nil
	}

	var item StoreItem
	if err := d.db.WithContext(ctx).
		Table(d.tableName).
		Where("access = ?", access).
		Find(&item).Error; err != nil {
		return nil, err
	}
	if item.ID == 0 {
		return nil, nil
	}

	return d.toTokenInfo(item.Data), nil
}

// GetByRefresh use the refresh token for token information data
func (d *Data) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	if refresh == "" {
		return nil, nil
	}

	var item StoreItem
	if err := d.db.WithContext(ctx).
		Table(d.tableName).
		Where("refresh = ?", refresh).
		Find(&item).Error; err != nil {
		return nil, err
	}
	if item.ID == 0 {
		return nil, nil
	}

	return d.toTokenInfo(item.Data), nil
}

func (d *Data) Stop() error {
	d.ticker.Stop()
	return nil
}

// StoreItem data item
type StoreItem struct {
	gorm.Model

	ExpiredAt int64
	Code      string `gorm:"type:varchar(512)"`
	Access    string `gorm:"type:varchar(512)"`
	Refresh   string `gorm:"type:varchar(512)"`
	Data      string `gorm:"type:text"`
}

// NewConfig create mysql configuration instance
func NewConfig(dsn string, dbType DBType, tableName string) *Config {
	return &Config{
		DSN:         dsn,
		DBType:      dbType,
		TableName:   tableName,
		MaxLifetime: time.Hour * 2,
	}
}

// Config gorm configuration
type Config struct {
	DSN         string
	DBType      DBType
	TableName   string
	MaxLifetime time.Duration
}

type DBType int8

const (
	MySQL = iota
)

// NewData .
func NewData(conf *MysqlConfig, gcInterval int) (*Data, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=%t&loc=%s",
		conf.User,
		conf.Pass,
		conf.Host,
		conf.Port,
		conf.DB,
		true,
		url.QueryEscape("Asia/Shanghai"))

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.New(
			stdlog.New(os.Stdout, "\r\n", stdlog.LstdFlags), // io writer
			logger.Config{
				SlowThreshold: time.Second, // slow SQL
				LogLevel:      logger.Info, // log level
				Colorful:      true,        // color
			},
		),
	})
	if err != nil {
		panic(err)
	}
	// default client pool
	s, err := db.DB()
	if err != nil {
		panic(err)
	}
	s.SetMaxIdleConns(conf.MaxIdle)
	s.SetMaxOpenConns(conf.MaxOpen)
	s.SetConnMaxLifetime(conf.MaxLife)
	return NewStoreWithDB(db, gcInterval), nil
}

func NewStoreWithDB(db *gorm.DB, gcInterval int) *Data {
	// https://github.com/techknowlogick/go-oauth2-gorm
	store := &Data{
		tableName:       "oauth2_token",
		clientTableName: "oauth2_client",
		usersTableName:  "oauth2_users",
		db:              db,
		stdout:          os.Stderr,
		ticker:          nil,
	}

	interval := 600
	if gcInterval > 0 {
		interval = gcInterval
	}
	store.ticker = time.NewTicker(time.Second * time.Duration(interval))

	if !db.Migrator().HasTable(store.usersTableName) {
		if err := db.Table(store.usersTableName).Migrator().CreateTable(&Users{}); err != nil {
			panic(err)
		}
	}

	if !db.Migrator().HasTable(store.tableName) {
		if err := db.Table(store.tableName).Migrator().CreateTable(&StoreItem{}); err != nil {
			panic(err)
		}
	}

	if !db.Migrator().HasTable(store.clientTableName) {
		if err := db.Table(store.clientTableName).Migrator().CreateTable(&Client{}); err != nil {
			panic(err)
		}
	}

	go store.gc()
	return store
}
