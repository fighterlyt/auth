package main

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/url"
	"os"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	_ "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Data .
type Data struct {
	clientTableName string
	usersTableName  string
	db              *gorm.DB
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

func (d *Data) UpdateToken(ctx context.Context, username string, token string) error {

	updates := d.db.Table(d.usersTableName).Where("username = ?", username).Updates(map[string]interface{}{
		"token": token,
	})
	if err := updates.Error; err != nil {
		return err
	}

	if updates.RowsAffected != 1 {
		return errors.New("更新失败")
	}

	return nil

}

func (d *Data) GetUserByUsername(ctx context.Context, username string) (user *Users, err error) {
	user = &Users{}

	if err := d.db.Table(d.usersTableName).Where("username = ?", username).First(user).Error; err != nil {
		return nil, err
	}

	return user, nil

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

// NewData .
func NewData(conf *MysqlConfig) (*Data, error) {
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
	return NewStoreWithDB(db), nil
}

func NewStoreWithDB(db *gorm.DB) *Data {
	// https://github.com/techknowlogick/go-oauth2-gorm
	store := &Data{
		clientTableName: "oauth2_client",
		usersTableName:  "oauth2_users",
		db:              db,
	}

	if !db.Migrator().HasTable(store.usersTableName) {
		if err := db.Table(store.usersTableName).Migrator().CreateTable(&Users{}); err != nil {
			panic(err)
		}
	}

	if !db.Migrator().HasTable(store.clientTableName) {
		if err := db.Table(store.clientTableName).Migrator().CreateTable(&Client{}); err != nil {
			panic(err)
		}
	}

	return store
}
