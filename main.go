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
	staticNamespace   string
	dynamicNamespace  string
	accessTokenExpiry time.Time
	client            *http.Client
	mutex             *sync.Mutex
}

func NewBlizzardClient(clientId string, clientSecret string) *BlizzardClient {
	return &BlizzardClient{
		clientId:         clientId,
		clientSecret:     clientSecret,
		staticNamespace:  "static-classic1x-us",
		dynamicNamespace: "dynamic-classic1x-us",
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

func (bc *BlizzardClient) GetRealms() ([]Realm, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "us.api.blizzard.com",
		Path:   "data/wow/search/connected-realm",
	}

	q := u.Query()
	q.Set("namespace", bc.dynamicNamespace)
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

	return realms, nil
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

func (bc *BlizzardClient) GetAuctionHouses(realmId int64) ([]AuctionHouse, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "us.api.blizzard.com",
		Path:   fmt.Sprintf("data/wow/connected-realm/%d/auctions/index", realmId),
	}

	q := u.Query()
	q.Set("namespace", bc.dynamicNamespace)
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

	var auctionHouses []AuctionHouse
	for _, auction := range responseObj.Auctions {
		auctionHouses = append(auctionHouses, AuctionHouse{Id: auction.Id, Name: auction.Name.EnUS})
	}

	return auctionHouses, nil
}

type bItemName struct {
	EnUS string `json:"en_US"`
}

type bItemQuality struct {
	Name bItemName `json:"name"`
}

type bItemPreviewItem struct {
	Name    bItemName    `json:"name"`
	Quality bItemQuality `json:"quality"`
}

type bItemResponse struct {
	Id            int32            `json:"id"`
	PreviewItem   bItemPreviewItem `json:"preview_item"`
	Level         int16            `json:"level"`
	RequiredLevel int16            `json:"required_level"`
	PurchasePrice int32            `json:"purchase_price"`
	SellPrice     int32            `json:"sell_price"`
}

type Item struct {
	Id            int32
	Name          string
	Quality       string
	Level         int16
	RequiredLevel int16
	PurchasePrice int32
	SellPrice     int32
}

func (bc *BlizzardClient) GetItem(itemId int32) (*Item, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "us.api.blizzard.com",
		Path:   fmt.Sprintf("data/wow/item/%d", itemId),
	}

	q := u.Query()
	q.Set("namespace", bc.staticNamespace)
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

	var responseObj bItemResponse
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return nil, err
	}

	return &Item{
		Id:            responseObj.Id,
		Name:          responseObj.PreviewItem.Name.EnUS,
		Quality:       responseObj.PreviewItem.Quality.Name.EnUS,
		Level:         responseObj.Level,
		RequiredLevel: responseObj.RequiredLevel,
		PurchasePrice: responseObj.PurchasePrice,
		SellPrice:     responseObj.SellPrice,
	}, nil
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

type bItemMediaAsset struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type bItemMediaResponse struct {
	Assets []bItemMediaAsset `json:"assets"`
}

func (bc *BlizzardClient) GetItemMedia(itemId int32) (string, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "us.api.blizzard.com",
		Path:   fmt.Sprintf("data/wow/media/item/%d", itemId),
	}

	q := u.Query()
	q.Set("namespace", bc.staticNamespace)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	accessToken, err := bc.getAccessToken()
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

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

	var responseObj bItemMediaResponse
	err = json.Unmarshal(body, &responseObj)
	if err != nil {
		return "", err
	}

	for _, asset := range responseObj.Assets {
		if asset.Key == "icon" {
			return asset.Value, nil
		}
	}

	return "", nil
}

func (bc *BlizzardClient) GetAuctions(realmId int64, auctionId int64) ([]*Auction, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "us.api.blizzard.com",
		Path:   fmt.Sprintf("data/wow/connected-realm/%d/auctions/%d", realmId, auctionId),
	}

	q := u.Query()
	q.Set("namespace", bc.dynamicNamespace)
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

	var auctions []*Auction
	for _, auction := range responseObj.Auctions {
		auctions = append(auctions, &Auction{
			Id:       auction.Id,
			ItemId:   auction.Item.Id,
			Bid:      auction.Bid,
			Buyout:   auction.Buyout,
			Quantity: auction.Quantity,
			TimeLeft: auction.TimeLeft,
		})
	}
	return auctions, nil
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
