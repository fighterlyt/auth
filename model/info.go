package model

type Info struct {
	UserID string `json:"user_id"`
}

type InfoResult struct {
	UserID  string `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
}
