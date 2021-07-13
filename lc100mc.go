package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
)

func startHTTPServer(codeCh chan string) (string, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", fmt.Errorf("failed to listen: %w", err)
	}
	url := fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		codeCh <- r.URL.Query().Get("code")
	})

	go http.Serve(listener, nil)
	return url, nil
}

func authorize(clientID string) (string, error) {
	codeCh := make(chan string)
	cbURL, err := startHTTPServer(codeCh)
	if err != nil {
		return "", fmt.Errorf("failed to start callback server: %w", err)
	}

	authQuery := url.Values{}
	authQuery.Set("client_id", clientID)
	authQuery.Set("redirect_uri", cbURL)
	authQuery.Set("response_type", "code")
	authQuery.Set("approval_prompt", "auto")
	authQuery.Set("scope", "activity:read")

	authURL := url.URL{
		Scheme:   "https",
		Host:     "www.strava.com",
		Path:     "/oauth/mobile/authorize",
		RawQuery: authQuery.Encode(),
	}
	open.Run(authURL.String())

	select {
	case code := <-codeCh:
		return code, nil
	}
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

func getAccessToken(clientID string, clientSecret string, code string) (string, error) {
	client := resty.New()

	resp, err := client.R().
		SetAuthToken("22ed1f5b423b0751744d972a4df5be23c1f815b2").
		SetQueryParam("client_id", clientID).
		SetQueryParam("client_secret", clientSecret).
		SetQueryParam("code", code).
		SetQueryParam("grant_type", "authorization_code").
		Post("https://www.strava.com/oauth/token")
	if err != nil {
		return "", fmt.Errorf("failed to get access token: %w", err)
	}

	var r TokenResponse
	if err := json.Unmarshal(resp.Body(), &r); err != nil {
		return "", fmt.Errorf("failed to decode auth response: %w", err)
	}

	return r.AccessToken, nil
}

type Activity struct {
	Type      string    `json:"type"`
	StartDate time.Time `json:"start_date"`
	Distance  float64   `json:"distance"`
}

type DailyDistance struct {
	RunWalk float64
	Bike    float64
	Row     float64
}

func NewDailyDistance(a Activity) DailyDistance {
	fmt.Printf("Processing activity %+v\n", a)

	var d DailyDistance

	dist := a.Distance * 0.000621371
	switch a.Type {
	case "Run":
		d.RunWalk = dist

	case "Walk":
		d.RunWalk = dist

	case "Hike":
		d.RunWalk = dist

	case "Ride":
		d.Bike = dist

	case "VirtualRide":
		d.Bike = dist

	case "Rowing":
		d.Row = dist
	}

	return d
}

func (d *DailyDistance) Add(other DailyDistance) {
	d.RunWalk += other.RunWalk
	d.Bike += other.Bike
	d.Row += other.Row
}

type DailyDistanceReport map[time.Time]DailyDistance

func getReport(token string) (DailyDistanceReport, error) {
	report := make(map[time.Time]DailyDistance)

	client := resty.New()
	resp, err := client.R().
		SetAuthToken(token).
		Get("https://www.strava.com/api/v3/athlete/activities?after=1609747140&per_page=100")
	if err != nil {
		return report, fmt.Errorf("failed to get access token: %w", err)
	}

	var r []Activity
	if err := json.Unmarshal(resp.Body(), &r); err != nil {
		return report, fmt.Errorf("failed to get activities: %w, %s", err, string(resp.Body()))
	}

	for _, a := range r {
		localDate := a.StartDate.Local()
		roundedDate := time.Date(
			localDate.Year(), localDate.Month(), localDate.Day(),
			0, 0, 0, 0, localDate.Location(),
		)

		d := NewDailyDistance(a)

		od, ok := report[roundedDate]
		if ok {
			od.Add(d)
		} else {
			od = d
		}
		report[roundedDate] = od
	}

	return report, nil
}

func summary(cmd *cobra.Command, args []string) {
	clientID, err := cmd.Flags().GetString("client-id")
	if err != nil || clientID == "" {
		fmt.Fprintln(os.Stderr, "Client ID is required")
		os.Exit(1)
	}

	clientSecret, err := cmd.Flags().GetString("client-secret")
	if err != nil || clientSecret == "" {
		fmt.Fprintln(os.Stderr, "Client secret is required")
		os.Exit(1)
	}

	code, err := authorize(clientID)
	if err != nil {
		panic(err)
	}

	token, err := getAccessToken(clientID, clientSecret, code)
	if err != nil {
		panic(err)
	}

	report, err := getReport(token)
	if err != nil {
		panic(err)
	}

	date := time.Date(
		2021, 1, 4,
		0, 0, 0, 0, time.Now().Location(),
	)
	dates := []string{""}
	runs := []string{"Run/Walk"}
	rides := []string{"Bike"}
	rows := []string{"Row"}

	for {
		dist := report[date]
		dates = append(dates, fmt.Sprintf("%d-%.3s", date.Day(), date.Month().String()))
		runs = append(runs, fmt.Sprintf("%.2f", dist.RunWalk))
		rides = append(rides, fmt.Sprintf("%.2f", dist.Bike))
		rows = append(rows, fmt.Sprintf("%.2f", dist.Row))
		date = date.AddDate(0, 0, 1)
		if date.After(time.Now()) {
			break
		}
	}

	fmt.Println(strings.Join(dates, ","))
	fmt.Println(strings.Join(runs, ","))
	fmt.Println(strings.Join(rides, ","))
	fmt.Println(strings.Join(rows, ","))
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "lc100mc",
		Short: "Cisco Life Connections 100 Mile Club Strava Utility",
		Long: `A utility that can summarize data from Strava activities for
Cisco Life Connections 100 Mile Club.`,
	}
	rootCmd.PersistentFlags().StringP("client-id", "c", "", "Strava Client ID")
	rootCmd.PersistentFlags().StringP("client-secret", "s", "", "Strava Client Secret")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "summary",
		Short: "Summarize qualifying activities",
		Run:   summary,
	})

	rootCmd.Execute()
}
