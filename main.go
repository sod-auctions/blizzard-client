package blizzard_client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type BlizzardClient struct {
	clientId          string
	clientSecret      string
	accessToken       string
	namespace         string
	accessTokenExpiry time.Time
	client            *http.Client
	mutex             *sync.Mutex
}

func NewBlizzardClient(clientId string, clientSecret string) *BlizzardClient {
	return &BlizzardClient{
		clientId:     clientId,
		clientSecret: clientSecret,
		namespace:    "dynamic-classic1x-us",
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		mutex: new(sync.Mutex),
	}
}

type bRealmSearchResponseName struct {
	EnUS string `json:"en_US"`
}

type bRealmSearchResponseRegion struct {
	Name bRealmSearchResponseName `json:"name"`
}

type bRealmSearchResponseRealm struct {
	Id       int64                      `json:"id"`
	Name     bRealmSearchResponseName   `json:"name"`
	Region   bRealmSearchResponseRegion `json:"region"`
	Category bRealmSearchResponseName   `json:"category"`
}

type bRealmSearchResponseData struct {
	Realms []*bRealmSearchResponseRealm `json:"realms"`
}

type bRealmSearchResponseResult struct {
	Data *bRealmSearchResponseData `json:"data"`
}

type bRealmSearchResponse struct {
	Results []*bRealmSearchResponseResult `json:"results"`
}

type Realm struct {
	Id   int64
	Name string
}

func (bc *BlizzardClient) GetRealms() (*[]Realm, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "us.api.blizzard.com",
		Path:   "data/wow/search/connected-realm",
	}

	q := u.Query()
	q.Set("namespace", bc.namespace)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	accessToken, err := bc.getAccessToken()
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := bc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server responded with status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var responseObj bRealmSearchResponse
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return nil, err
	}

	var realms []Realm
	for _, result := range responseObj.Results {
		for _, realm := range result.Data.Realms {
			if realm.Region.Name.EnUS == "Classic Era North America" && realm.Category.EnUS == "Seasonal" {
				realms = append(realms, Realm{Id: realm.Id, Name: realm.Name.EnUS})
			}
		}
	}

	return &realms, nil
}

type bAuctionHouseName struct {
	EnUS string `json:"en_US"`
}

type bAuctionHouseAuction struct {
	Id   int64             `json:"id"`
	Name bAuctionHouseName `json:"name"`
}

type bAuctionHouseResponse struct {
	Auctions []*bAuctionHouseAuction `json:"auctions"`
}

type AuctionHouse struct {
	Id   int64
	Name string
}

func (bc *BlizzardClient) GetAuctionHouses(realmId int64) (*[]AuctionHouse, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "us.api.blizzard.com",
		Path:   fmt.Sprintf("data/wow/connected-realm/%d/auctions/index", realmId),
	}

	q := u.Query()
	q.Set("namespace", bc.namespace)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	accessToken, err := bc.getAccessToken()
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := bc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server responded with status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var responseObj bAuctionHouseResponse
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return nil, err
	}

	var auctions []AuctionHouse
	for _, auction := range responseObj.Auctions {
		auctions = append(auctions, AuctionHouse{Id: auction.Id, Name: auction.Name.EnUS})
	}

	return &auctions, nil
}

type bAuctionItem struct {
	Id int64 `json:"id"`
}

type bAuction struct {
	Id       int64        `json:"id"`
	Item     bAuctionItem `json:"item"`
	Bid      int64        `json:"bid"`
	Buyout   int64        `json:"buyout"`
	Quantity int64        `json:"quantity"`
	TimeLeft string       `json:"time_left"`
}

type bAuctionResponse struct {
	Auctions []*bAuction `json:"auctions"`
}

type Auction struct {
	Id       int64
	ItemId   int64
	Bid      int64
	Buyout   int64
	Quantity int64
	TimeLeft string
}

func (bc *BlizzardClient) GetAuctions(realmId int64, auctionId int64) (*[]Auction, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "us.api.blizzard.com",
		Path:   fmt.Sprintf("data/wow/connected-realm/%d/auctions/%d", realmId, auctionId),
	}

	q := u.Query()
	q.Set("namespace", bc.namespace)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	accessToken, err := bc.getAccessToken()
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	resp, err := bc.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server responded with status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var responseObj bAuctionResponse
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return nil, err
	}

	var auctions []Auction
	for _, auction := range responseObj.Auctions {
		auctions = append(auctions, Auction{
			Id:       auction.Id,
			ItemId:   auction.Item.Id,
			Bid:      auction.Bid,
			Buyout:   auction.Buyout,
			Quantity: auction.Quantity,
			TimeLeft: auction.TimeLeft,
		})
	}
	return &auctions, nil
}

type boAuthResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Sub         string `json:"sub"`
}

func (bc *BlizzardClient) getAccessToken() (string, error) {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if bc.accessToken != "" && time.Now().Before(bc.accessTokenExpiry) {
		return bc.accessToken, nil
	}

	u := url.URL{
		Scheme: "https",
		Host:   "oauth.battle.net",
		Path:   "token",
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(bc.clientId, bc.clientSecret)

	resp, err := bc.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server responded with status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var responseObj boAuthResponse
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return "", err
	}

	bc.accessToken = responseObj.AccessToken
	bc.accessTokenExpiry = time.Now().Add(time.Second * time.Duration(responseObj.ExpiresIn-10))

	return bc.accessToken, nil
}
