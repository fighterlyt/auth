package session

import (
	"github.com/gorilla/sessions"
	"net/http"
)

var sessionStore = sessions.NewCookieStore([]byte("123456"))

func init() {
	//sessionStore.Options.Domain="localhost"
	//sessionStore.Options.Path="/"
	sessionStore.Options.MaxAge=0  //关掉浏览器就清掉session
}


// oauth2 服务端使用： 保存当前用户登录的ID
func SaveUserSession(r *http.Request,w http.ResponseWriter,userID string)(err error){
		s,err:=sessionStore.Get(r,"LoginUser")
		if err!=nil{
			return err
		}
		s.Values["userID"]=userID
		err=s.Save(r,w)//save 保存
		if err!=nil{
			return err
		}

		return nil
}

// oauth2 服务端使用： 获取当前用户登录的ID
func GetUserSession(r *http.Request)   string{
	if s,err:=sessionStore.Get(r,"LoginUser");err==nil{
		if s.Values["userID"]!=nil{
			return s.Values["userID"].(string)
		}
	}
	return ""
}
