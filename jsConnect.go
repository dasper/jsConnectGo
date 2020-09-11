package vanillaforums

import (
	"crypto"
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
)

var clientID int
var secret string
var secure crypto.Hash

type Auth struct {
	User
	ClientID  int    `json:"client_id"`
	Signature string `json:"signature"`
}

type SSO struct {
	User
	ClientID int `json:"client_id"`
}

type User struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	PhotoURL string `json:"photourl"`
	Roles    string `json:"roles"`
	UniqueID int    `json:"uniqueid"`
}

var userFields map[string]interface{}
var allowedAlgorithms map[string]crypto.Hash

func init() {
	secure = crypto.MD5
	allowedAlgorithms["MD5"] = crypto.MD5
	allowedAlgorithms["SHA1"] = crypto.SHA1
	allowedAlgorithms["SHA256"] = crypto.SHA256
}

func SetSigningAlgorithm(algo string) error {
	value, ok := allowedAlgorithms[algo]
	if !ok {
		return errors.New("Algorithm not allowed")
	}
	secure = value
	return nil
}

func SetSigningCredentials(public int, private string) {
	clientID = public
	secret = private
}

func WriteJsConnect(user User) (reply Auth) {
	reply.ClientID = clientID
	reply.UniqueID = user.UniqueID
	reply.Email = user.Email
	reply.PhotoURL = user.PhotoURL
	reply.Name = user.Name
	reply.Roles = user.Roles
	reply.Signature, _ = createHash(user.QueryString()+secret, secure)
	return
}

func (r *User) QueryString() string {
	params := url.Values{}
	params.Add("email", r.Email)
	params.Add("name", r.Name)
	params.Add("photourl", r.PhotoURL)
	params.Add("roles", r.Roles)
	params.Add("uniqueid", strconv.Itoa(r.UniqueID))

	return params.Encode()
}

func SetUserField(key, value string) {

}

func SignJsConnect() {}

func (user User) SSOString() (result string, err error) {
	sso := SSO{User: user}
	sso.ClientID = clientID
	json, err := json.Marshal(sso)
	result = base64.StdEncoding.EncodeToString(json)
	return
}

func createHash(text string, hash crypto.Hash) (string, error) {
	if !hash.Available() {
		return "", errors.New("Algorithm not allowed")
	}
	h := hash.New()
	io.WriteString(h, text)
	return hex.EncodeToString(h.Sum(nil)), nil
}
