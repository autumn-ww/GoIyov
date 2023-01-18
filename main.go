package main

import (
	"fmt"
	"goiyov/entity"
	"goiyov/proxy"
	"io"
	"io/ioutil"
	"net/http"
	"time"
	"unicode"
)

type Handler struct {
	proxy.Delegate
}

func ReadBody(flag string, entity *entity.Entity, body io.ReadCloser) {
	if body == nil {
		return
	}
	bodyBytes, err := ioutil.ReadAll(body)
	if err == nil {
		bodyStr := string(bodyBytes)
		isLetter := true
		if len(bodyStr) > 10 {
			for _, r := range bodyStr[0:10] {
				if !unicode.IsLetter(r) &&
					r != '=' &&
					r != '&' &&
					r != '%' &&
					r != '{' &&
					r != '}' &&
					r != '[' &&
					r != ']' &&
					r != ',' &&
					r != '"' &&
					r != ':' &&
					r != '.' && !unicode.IsNumber(r) {
					isLetter = false
					break
				}
			}
			if isLetter {
				uri := entity.Request.URL
				hostUri := uri.String()
				fmt.Printf("%s url:%s %+v\n", flag, hostUri, bodyStr)
			}
		}

	}
}
func (handler *Handler) BeforeRequest(entity *entity.Entity) {
	body := entity.GetRequestBody()
	ReadBody("request", entity, body)
}
func (handler *Handler) BeforeResponse(entity *entity.Entity, err error) {
	body := entity.GetResponseBody()
	ReadBody("response", entity, body)
}
func (handler *Handler) ErrorLog(err error) {}

func main() {
	proxy := proxy.NewWithDelegate(&Handler{})
	server := &http.Server{
		Addr: ":8888",
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			proxy.ServerHandler(rw, req)
		}),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
