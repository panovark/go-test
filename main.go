package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// --- In-Memory Database ---

type User struct {
	Username string
	Password string
}

type Order struct {
	ID            string
	Price         int64
	Quantity      int64
	DeliveryStart int64
	DeliveryEnd   int64
	Owner         string // Seller Username
	Status        string // "OPEN", "FILLED"
}

type Trade struct {
	ID        string
	BuyerID   string
	SellerID  string
	Price     int64
	Quantity  int64
	Timestamp int64
}

var (
	mu           sync.RWMutex
	users        = make(map[string]User)   // Username -> User
	tokens       = make(map[string]string) // Token -> Username
	orders       = make(map[string]*Order) // ID -> Order
	trades       = make([]*Trade, 0)       // History of trades
	orderCounter int64 = 0
)

// --- GalacticBuf Protocol Implementation ---

const (
	TypeInt    = 0x01
	TypeString = 0x02
	TypeList   = 0x03
	TypeObject = 0x04
)

type GValue interface{}

// EncodeMessage converts a map to GalacticBuf bytes
func EncodeMessage(data map[string]GValue) ([]byte, error) {
	bodyBuffer := new(bytes.Buffer)
	if err := writeFields(bodyBuffer, data); err != nil {
		return nil, err
	}
	bodyBytes := bodyBuffer.Bytes()

	header := new(bytes.Buffer)
	header.WriteByte(0x01)            // Version
	header.WriteByte(byte(len(data))) // Field Count
	totalLen := 4 + len(bodyBytes)
	binary.Write(header, binary.BigEndian, uint16(totalLen))

	return append(header.Bytes(), bodyBytes...), nil
}

func writeFields(buf *bytes.Buffer, data map[string]GValue) error {
	for name, val := range data {
		// Field Name Length
		if len(name) > 255 {
			return fmt.Errorf("field name too long")
		}
		buf.WriteByte(byte(len(name)))
		// Field Name
		buf.WriteString(name)

		switch v := val.(type) {
		case int64:
			buf.WriteByte(TypeInt)
			binary.Write(buf, binary.BigEndian, v)
		case int:
			buf.WriteByte(TypeInt)
			binary.Write(buf, binary.BigEndian, int64(v))
		case string:
			buf.WriteByte(TypeString)
			if len(v) > 65535 {
				return fmt.Errorf("string too long")
			}
			binary.Write(buf, binary.BigEndian, uint16(len(v)))
			buf.WriteString(v)
		case []map[string]GValue: // List of Objects
			buf.WriteByte(TypeList)
			buf.WriteByte(TypeObject)                           // Element Type
			binary.Write(buf, binary.BigEndian, uint16(len(v))) // Element Count
			for _, obj := range v {
				buf.WriteByte(byte(len(obj))) // Field count for object
				if err := writeFields(buf, obj); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unsupported type for encoding: %T", v)
		}
	}
	return nil
}

// DecodeMessage parses GalacticBuf bytes to a map
func DecodeMessage(r io.Reader) (map[string]GValue, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		// Handle empty body gracefully if needed, though protocol says header exists
		if err == io.EOF {
			return nil, err
		}
		return nil, err
	}
	if header[0] != 0x01 {
		return nil, fmt.Errorf("invalid protocol version")
	}
	fieldCount := int(header[1])
	return readFields(r, fieldCount)
}

func readFields(r io.Reader, count int) (map[string]GValue, error) {
	result := make(map[string]GValue)
	for i := 0; i < count; i++ {
		var nameLen uint8
		if err := binary.Read(r, binary.BigEndian, &nameLen); err != nil {
			return nil, err
		}
		nameBytes := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nameBytes); err != nil {
			return nil, err
		}
		fieldName := string(nameBytes)

		var typeInd uint8
		if err := binary.Read(r, binary.BigEndian, &typeInd); err != nil {
			return nil, err
		}
		val, err := readValue(r, typeInd)
		if err != nil {
			return nil, err
		}
		result[fieldName] = val
	}
	return result, nil
}

func readValue(r io.Reader, typeInd uint8) (GValue, error) {
	switch typeInd {
	case TypeInt:
		var v int64
		if err := binary.Read(r, binary.BigEndian, &v); err != nil {
			return nil, err
		}
		return v, nil
	case TypeString:
		var l uint16
		if err := binary.Read(r, binary.BigEndian, &l); err != nil {
			return nil, err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf), nil
	case TypeList:
		var elemType uint8
		binary.Read(r, binary.BigEndian, &elemType)
		var count uint16
		binary.Read(r, binary.BigEndian, &count)
		list := make([]GValue, 0, count)
		for k := 0; k < int(count); k++ {
			if elemType == TypeObject {
				var fc uint8
				binary.Read(r, binary.BigEndian, &fc)
				obj, _ := readFields(r, int(fc))
				list = append(list, obj)
			} else {
				v, _ := readValue(r, elemType)
				list = append(list, v)
			}
		}
		return list, nil
	case TypeObject:
		var fc uint8
		binary.Read(r, binary.BigEndian, &fc)
		return readFields(r, int(fc))
	default:
		return nil, fmt.Errorf("unknown type %x", typeInd)
	}
}

// --- Helpers ---

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func getUserFromToken(r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", false
	}
	token := authHeader[7:]
	mu.RLock()
	defer mu.RUnlock()
	user, ok := tokens[token]
	return user, ok
}

// --- HTTP Handlers ---

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// POST /register
func registerHandler(w http.ResponseWriter, r *http.Request) {
	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	username, _ := data["username"].(string)
	password, _ := data["password"].(string)

	if username == "" || password == "" {
		http.Error(w, "Empty fields", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := users[username]; exists {
		http.Error(w, "Conflict", http.StatusConflict)
		return
	}
	users[username] = User{Username: username, Password: password}
	w.WriteHeader(http.StatusNoContent)
}

// POST /login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	username, _ := data["username"].(string)
	password, _ := data["password"].(string)

	mu.Lock()
	defer mu.Unlock()
	u, exists := users[username]
	if !exists || u.Password != password {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := generateToken()
	tokens[token] = username

	resp := map[string]GValue{"token": token}
	encoded, _ := EncodeMessage(resp)
	w.Header().Set("Content-Type", "application/x-galacticbuf")
	w.Write(encoded)
}

// PUT /user/password (Change Password)
func passwordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := DecodeMessage(r.Body)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	username, _ := data["username"].(string)
	oldPass, _ := data["old_password"].(string)
	newPass, _ := data["new_password"].(string)

	if username == "" || oldPass == "" || newPass == "" {
		http.Error(w, "Empty fields", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	u, exists := users[username]
	if !exists || u.Password != oldPass {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 1. Change Password
	u.Password = newPass
	users[username] = u

	// 2. Invalidate ALL existing tokens for this user
	// Note: Deleting from map while iterating is safe in Go
	for token, user := range tokens {
		if user == username {
			delete(tokens, token)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET /orders (List) & POST /orders (Submit)
func ordersHandler(w http.ResponseWriter, r *http.Request) {
	
	// --- LIST ORDERS (GET - Public) ---
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		startStr := q.Get("delivery_start")
		endStr := q.Get("delivery_end")

		if startStr == "" || endStr == "" {
			http.Error(w, "Missing query params", http.StatusBadRequest)
			return
		}

		start, err1 := strconv.ParseInt(startStr, 10, 64)
		end, err2 := strconv.ParseInt(endStr, 10, 64)
		if err1 != nil || err2 != nil {
			http.Error(w, "Invalid timestamps", http.StatusBadRequest)
			return
		}

		mu.RLock()
		var filtered []*Order
		for _, o := range orders {
			if o.Status == "OPEN" && o.DeliveryStart == start && o.DeliveryEnd == end {
				filtered = append(filtered, o)
			}
		}
		mu.RUnlock()

		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].Price < filtered[j].Price
		})

		list := make([]map[string]GValue, 0, len(filtered))
		for _, o := range filtered {
			list = append(list, map[string]GValue{
				"order_id":       o.ID,
				"price":          o.Price,
				"quantity":       o.Quantity,
				"delivery_start": o.DeliveryStart,
				"delivery_end":   o.DeliveryEnd,
			})
		}

		resp := map[string]GValue{"orders": list}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}

	// --- SUBMIT ORDER (POST - Auth Required) ---
	if r.Method == http.MethodPost {
		username, authOk := getUserFromToken(r)
		if !authOk {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		data, err := DecodeMessage(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		price, ok1 := data["price"].(int64)
		quantity, ok2 := data["quantity"].(int64)
		start, ok3 := data["delivery_start"].(int64)
		end, ok4 := data["delivery_end"].(int64)

		if !ok1 || !ok2 || !ok3 || !ok4 {
			http.Error(w, "Missing fields", http.StatusBadRequest)
			return
		}
		if quantity <= 0 {
			http.Error(w, "Quantity must be positive", http.StatusBadRequest)
			return
		}
		const hourMs = 3600000
		if start%hourMs != 0 || end%hourMs != 0 || end <= start || (end-start) != hourMs {
			http.Error(w, "Invalid Contract Timestamps", http.StatusBadRequest)
			return
		}

		mu.Lock()
		orderCounter++
		orderID := fmt.Sprintf("ord-%d", orderCounter)
		newOrder := &Order{
			ID:            orderID,
			Price:         price,
			Quantity:      quantity,
			DeliveryStart: start,
			DeliveryEnd:   end,
			Owner:         username,
			Status:        "OPEN",
		}
		orders[orderID] = newOrder
		mu.Unlock()

		resp := map[string]GValue{"order_id": orderID}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}
}

// GET /trades (List) & POST /trades (Take)
func tradesHandler(w http.ResponseWriter, r *http.Request) {
	
	// --- LIST TRADES (GET - Public) ---
	if r.Method == http.MethodGet {
		mu.RLock()
		// Make a copy to sort
		resultTrades := make([]*Trade, len(trades))
		copy(resultTrades, trades)
		mu.RUnlock()

		// Sort: Newest first (Descending Timestamp)
		sort.Slice(resultTrades, func(i, j int) bool {
			return resultTrades[i].Timestamp > resultTrades[j].Timestamp
		})

		list := make([]map[string]GValue, 0, len(resultTrades))
		for _, t := range resultTrades {
			list = append(list, map[string]GValue{
				"trade_id":  t.ID,
				"buyer_id":  t.BuyerID,
				"seller_id": t.SellerID,
				"price":     t.Price,
				"quantity":  t.Quantity,
				"timestamp": t.Timestamp,
			})
		}

		resp := map[string]GValue{"trades": list}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}

	// --- TAKE ORDER (POST - Auth Required) ---
	if r.Method == http.MethodPost {
		buyerUser, authOk := getUserFromToken(r)
		if !authOk {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		data, err := DecodeMessage(r.Body)
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		orderID, ok := data["order_id"].(string)
		if !ok {
			http.Error(w, "Missing order_id", http.StatusBadRequest)
			return
		}

		mu.Lock()
		defer mu.Unlock()

		order, exists := orders[orderID]
		if !exists || order.Status != "OPEN" {
			http.Error(w, "Order not found or inactive", http.StatusNotFound)
			return
		}

		// Update Order Status
		order.Status = "FILLED"
		
		// Create Trade Record
		now := time.Now().UnixMilli() // Milliseconds usually required for these timestamps
		tradeID := fmt.Sprintf("trd-%s-%d", order.ID, now)
		
		newTrade := &Trade{
			ID:        tradeID,
			BuyerID:   buyerUser,
			SellerID:  order.Owner,
			Price:     order.Price,
			Quantity:  order.Quantity,
			Timestamp: now,
		}
		trades = append(trades, newTrade)

		resp := map[string]GValue{"trade_id": tradeID}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
	}
}

// Log wrapper
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		next(w, r)
	}
}

func main() {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/user/password", passwordHandler) // New endpoint
	mux.HandleFunc("/orders", ordersHandler)
	mux.HandleFunc("/trades", tradesHandler)

	log.Println("Galactic Exchange started on :8080")
	if err := http.ListenAndServe(":8080", loggingMiddleware(mux.ServeHTTP)); err != nil {
		log.Fatal(err)
	}
}