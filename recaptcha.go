// This package verifies reCaptcha v3 (http://www.google.com/recaptcha) responses
package recaptcha

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/appengine"
	"google.golang.org/appengine/urlfetch"
)

// google recaptcha response
type recaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       float32   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

// recaptcha api endpoint
const (
	requestTimeout  = time.Second * 10
	recaptchaServer = "https://www.google.com/recaptcha/api/siteverify"
)

// main object
type Recaptcha struct {
	PrivateKey string
}

// check : initiate a recaptcha verify request
func (r *Recaptcha) requestVerify(request *http.Request, remoteAddr net.IP, captchaResponse string) (recaptchaResponse, error) {
	// fire off request with a timeout of 10 seconds
	ctx := appengine.NewContext(request)
	client := urlfetch.Client(ctx)
	resp, err := client.PostForm(
		recaptchaServer,
		url.Values{
			"secret":   {r.PrivateKey},
			"remoteip": {remoteAddr.String()},
			"response": {captchaResponse},
		},
	)

	// request failed
	if err != nil {
		return recaptchaResponse{Success: false}, err
	}

	// close response when function exits
	defer resp.Body.Close()

	// read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return recaptchaResponse{Success: false}, err
	}

	// parse json to our response object
	var response recaptchaResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return recaptchaResponse{Success: false}, err
	}

	// return our object response
	return response, nil
}

// Check : check user IP, captcha subject (= page) and captcha response but return treshold
func (r *Recaptcha) Check(request *http.Request, remoteip net.IP, action string, response string) (success bool, score float32, err error) {
	resp, err := r.requestVerify(request, remoteip, response)
	// fetch/parsing failed
	if err != nil {
		return false, 0, err
	}

	// captcha subject did not match
	if strings.ToLower(resp.Action) != strings.ToLower(action) {
		return false, 0, errors.New("recaptcha actions do not match")
	}

	// recaptcha token was not valid
	if !resp.Success {
		return false, 0, nil
	}

	// user treshold was not enough
	return true, resp.Score, nil
}
