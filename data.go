package main

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/url"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Data .
type Data struct {
	clientTableName string
	db              *gorm.DB
}

type Client struct {
	ID       int64  `gorm:"column:id;primaryKey;type:bigint(20);comment:记录id" json:"id"`
	Username string `gorm:"column:username;type:varchar(255)" json:"username"`
	Domain   string `gorm:"column:domain;type:varchar(255)" json:"domain"`
	Remark   string `gorm:"column:remark;type:varchar(255)" json:"remark"`
	IP       string `gorm:"column:ip;type:varchar(32);comment:ip" json:"ip"`
}

func (c *Client) TableName() string {
	return "oauth2_client"
}

func (c *Client) GetDomain() string {
	return c.Domain
}

func (d *Data) UpdateToken(ctx context.Context, username string, token string) error {

	updates := d.db.Model(&Users{}).Where("username = ?", username).Updates(map[string]interface{}{
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

	if err := d.db.Model(&Users{}).Preload("Clients").Where("username = ?", username).First(user).Error; err != nil {
		return nil, err
	}

	return user, nil

}

func (d *Data) GetUser(ctx context.Context, username string, password string) (user *Users, err error) {
	user = &Users{}

	if err := d.db.Model(&Users{}).Where("username = ? and password = ?", username, password).First(user).Error; err != nil {
		return nil, err
	}

	return user, nil

}

type ClientInfo struct {
	Domain string `gorm:"column:domain;type:varchar(255)" json:"domain"`
	Remark string `gorm:"column:remark;type:varchar(255)" json:"remark"`
}

func (d *Data) GetClients(ctx context.Context, username string) ([]*ClientInfo, error) {
	var infos []*ClientInfo

	if err := d.db.Model(&Client{}).Select("domain", "remark").Where("username = ?", username).Find(&infos).Error; err != nil {
		return nil, err
	}

	return infos, nil
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
		db: db,
	}

	if err := db.AutoMigrate(&Users{}, &Client{}); err != nil {
		panic(err)
	}

	return store
}
