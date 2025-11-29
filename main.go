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
	Owner         string // Username
	Status        string // "OPEN", "FILLED"
}

var (
	mu      sync.RWMutex
	users   = make(map[string]User)   // Username -> User
	tokens  = make(map[string]string) // Token -> Username
	orders  = make(map[string]*Order) // ID -> Order
	// Для генерации ID
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
		// Name Len
		var nameLen uint8
		if err := binary.Read(r, binary.BigEndian, &nameLen); err != nil {
			return nil, err
		}
		// Name
		nameBytes := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nameBytes); err != nil {
			return nil, err
		}
		fieldName := string(nameBytes)
		// Type
		var typeInd uint8
		if err := binary.Read(r, binary.BigEndian, &typeInd); err != nil {
			return nil, err
		}
		// Value
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

// POST /orders (Submit Orders)
// GET /orders (List Orders - assumed requirement)
func ordersHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Authentication Check
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := authHeader[7:]

	mu.RLock()
	username, authOk := tokens[token]
	mu.RUnlock()

	if !authOk {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		// SUBMIT ORDER
		data, err := DecodeMessage(r.Body)
		if err != nil {
			log.Printf("Order decode error: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Extract and Validate Fields
		price, ok1 := data["price"].(int64)
		quantity, ok2 := data["quantity"].(int64)
		start, ok3 := data["delivery_start"].(int64)
		end, ok4 := data["delivery_end"].(int64)

		if !ok1 || !ok2 || !ok3 || !ok4 {
			http.Error(w, "Missing/Invalid fields", http.StatusBadRequest)
			return
		}

		// Logic Validation
		// 1. Quantity must be positive
		if quantity <= 0 {
			http.Error(w, "Quantity must be positive", http.StatusBadRequest)
			return
		}
		// 2. Timestamps aligned to 1-hour boundaries (3600000 ms)
		const hourMs = 3600000
		if start%hourMs != 0 || end%hourMs != 0 {
			http.Error(w, "Timestamps not aligned", http.StatusBadRequest)
			return
		}
		// 3. End > Start
		if end <= start {
			http.Error(w, "End must be > Start", http.StatusBadRequest)
			return
		}
		// 4. Duration exactly 1 hour
		if (end - start) != hourMs {
			http.Error(w, "Duration must be 1 hour", http.StatusBadRequest)
			return
		}

		// Create Order
		mu.Lock()
		orderCounter++
		orderID := fmt.Sprintf("ord-%d-%s", orderCounter, username)
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

		// Response
		resp := map[string]GValue{"order_id": orderID}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
		return
	}

	if r.Method == http.MethodGet {
		// LIST ORDERS (Simple implementation)
		mu.RLock()
		defer mu.RUnlock()
		
		// Typically list orders returns a list of objects
		list := make([]map[string]GValue, 0)
		for _, o := range orders {
			if o.Status == "OPEN" {
				list = append(list, map[string]GValue{
					"id":             o.ID,
					"price":          o.Price,
					"quantity":       o.Quantity,
					"delivery_start": o.DeliveryStart,
					"delivery_end":   o.DeliveryEnd,
				})
			}
		}
		resp := map[string]GValue{"orders": list}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
	}
}

// POST /trades (Take Order) - from previous context
func tradesHandler(w http.ResponseWriter, r *http.Request) {
	// Auth check
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := authHeader[7:]
	mu.RLock()
	_, authOk := tokens[token]
	mu.RUnlock()
	if !authOk {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
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
			http.Error(w, "Order not found/filled", http.StatusNotFound)
			return
		}

		order.Status = "FILLED"
		tradeID := fmt.Sprintf("trd-%d", time.Now().UnixNano())

		resp := map[string]GValue{"trade_id": tradeID}
		encoded, _ := EncodeMessage(resp)
		w.Header().Set("Content-Type", "application/x-galacticbuf")
		w.Write(encoded)
	}
}

// Middleware to log requests (helps debug)
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		
		log.Printf("REQ: %s %s", r.Method, r.URL.Path)
		if len(body) > 0 {
			log.Printf("BODY (Hex): %s", hex.EncodeToString(body))
		}
		next(w, r)
	}
}

func main() {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/orders", ordersHandler)
	mux.HandleFunc("/trades", tradesHandler)

	log.Println("Galactic Exchange started on :8080")
	if err := http.ListenAndServe(":8080", loggingMiddleware(mux.ServeHTTP)); err != nil {
		log.Fatal(err)
	}
}