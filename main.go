package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// --- Хранилище данных (In-Memory Database) ---
// В реальности здесь была бы БД, но для хакатона хватит мапы с мьютексом.
type Order struct {
	ID     string
	Price  int64
	Status string // "OPEN", "FILLED"
}

var (
	ordersMutex sync.RWMutex
	orders      = map[string]*Order{
		// Добавим тестовый ордер, чтобы можно было проверить
		"order_123": {ID: "order_123", Price: 500, Status: "OPEN"},
	}
)

// --- GalacticBuf Constants ---
const (
	TypeInt    = 0x01
	TypeString = 0x02
	TypeList   = 0x03
	TypeObject = 0x04
)

// --- GalacticBuf Serialization Logic ---

// GValue - универсальная обертка для значений
type GValue interface{}

// EncodeMessage создает полное сообщение GalacticBuf (Header + Fields)
func EncodeMessage(data map[string]GValue) ([]byte, error) {
	bodyBuffer := new(bytes.Buffer)
	
	// Пишем поля (Field Count будет вычислен из длины мапы)
	if err := writeFields(bodyBuffer, data); err != nil {
		return nil, err
	}
	bodyBytes := bodyBuffer.Bytes()

	// Создаем заголовок
	header := new(bytes.Buffer)
	// Byte 0: Version
	header.WriteByte(0x01)
	// Byte 1: Field Count
	header.WriteByte(byte(len(data)))
	// Bytes 2-3: Total Length (Header 4 bytes + Body length)
	totalLen := 4 + len(bodyBytes)
	if totalLen > 65535 {
		return nil, fmt.Errorf("message too large")
	}
	binary.Write(header, binary.BigEndian, uint16(totalLen))

	return append(header.Bytes(), bodyBytes...), nil
}

func writeFields(buf *bytes.Buffer, data map[string]GValue) error {
	for name, val := range data {
		// 1. Field Name Length
		if len(name) > 255 {
			return fmt.Errorf("field name too long")
		}
		buf.WriteByte(byte(len(name)))
		// 2. Field Name
		buf.WriteString(name)

		// 3. Type & 4. Value
		switch v := val.(type) {
		case int64:
			buf.WriteByte(TypeInt)
			binary.Write(buf, binary.BigEndian, v)
		case int: // Helper for literals
			buf.WriteByte(TypeInt)
			binary.Write(buf, binary.BigEndian, int64(v))
		case string:
			buf.WriteByte(TypeString)
			if len(v) > 65535 {
				return fmt.Errorf("string too long")
			}
			binary.Write(buf, binary.BigEndian, uint16(len(v)))
			buf.WriteString(v)
		// Для простоты задачи List и Object здесь опущены в Encod'ере (для ответа нам нужны только String trade_id),
		// но если нужно отправлять списки, логика аналогична Decoder'у ниже.
		default:
			return fmt.Errorf("unsupported type for encoding: %T", v)
		}
	}
	return nil
}

// DecodeMessage парсит входящие байты в мапу
func DecodeMessage(r io.Reader) (map[string]GValue, error) {
	// 1. Read Header (4 bytes)
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] != 0x01 {
		return nil, fmt.Errorf("invalid protocol version")
	}
	fieldCount := int(header[1])
	// Total length нам не особо нужен для стримингового чтения, но можно проверить
	
	return readFields(r, fieldCount)
}

func readFields(r io.Reader, count int) (map[string]GValue, error) {
	result := make(map[string]GValue)
	
	for i := 0; i < count; i++ {
		// a. Name Length
		var nameLen uint8
		if err := binary.Read(r, binary.BigEndian, &nameLen); err != nil {
			return nil, err
		}
		
		// b. Name
		nameBytes := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nameBytes); err != nil {
			return nil, err
		}
		fieldName := string(nameBytes)

		// c. Type Indicator
		var typeInd uint8
		if err := binary.Read(r, binary.BigEndian, &typeInd); err != nil {
			return nil, err
		}

		// d. Value
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
		var strLen uint16
		if err := binary.Read(r, binary.BigEndian, &strLen); err != nil {
			return nil, err
		}
		strBytes := make([]byte, strLen)
		if _, err := io.ReadFull(r, strBytes); err != nil {
			return nil, err
		}
		return string(strBytes), nil
	case TypeList:
		var elemType uint8
		if err := binary.Read(r, binary.BigEndian, &elemType); err != nil {
			return nil, err
		}
		var elemCount uint16
		if err := binary.Read(r, binary.BigEndian, &elemCount); err != nil {
			return nil, err
		}
		list := make([]GValue, 0, elemCount)
		for k := 0; k < int(elemCount); k++ {
			if elemType == TypeObject {
				// Object in list has no outer header, just field count + fields
				var fieldCount uint8
				if err := binary.Read(r, binary.BigEndian, &fieldCount); err != nil {
					return nil, err
				}
				obj, err := readFields(r, int(fieldCount))
				if err != nil {
					return nil, err
				}
				list = append(list, obj)
			} else {
				v, err := readValue(r, elemType)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
		}
		return list, nil
	case TypeObject:
		var fieldCount uint8
		if err := binary.Read(r, binary.BigEndian, &fieldCount); err != nil {
			return nil, err
		}
		return readFields(r, int(fieldCount))
	default:
		return nil, fmt.Errorf("unknown type: %x", typeInd)
	}
}

// --- HTTP Handlers ---

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func tradesHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Auth Check (Prerequisite)
	// Простейшая проверка наличия заголовка Authorization
	if r.Header.Get("Authorization") == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Читаем тело запроса (GalacticBuf)
	data, err := DecodeMessage(r.Body)
	if err != nil {
		log.Printf("Decode error: %v", err)
		http.Error(w, "Bad Request: Invalid GalacticBuf", http.StatusBadRequest)
		return
	}

	// 3. Извлекаем order_id
	orderIDVal, ok := data["order_id"]
	if !ok {
		http.Error(w, "Bad Request: missing order_id", http.StatusBadRequest)
		return
	}
	orderID, ok := orderIDVal.(string)
	if !ok {
		http.Error(w, "Bad Request: order_id must be string", http.StatusBadRequest)
		return
	}

	// 4. Логика сделки
	ordersMutex.Lock()
	order, exists := orders[orderID]
	
	if !exists || order.Status != "OPEN" {
		ordersMutex.Unlock()
		http.Error(w, "Order not found or not active", http.StatusNotFound)
		return
	}

	// "Fill" the order
	order.Status = "FILLED"
	ordersMutex.Unlock()

	// Генерируем trade_id
	tradeID := fmt.Sprintf("trade_%d_%s", time.Now().Unix(), orderID)

	// 5. Формируем ответ (GalacticBuf)
	responseData := map[string]GValue{
		"trade_id": tradeID,
	}
	
	encodedResp, err := EncodeMessage(responseData)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(encodedResp)
}

func main() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/trades", tradesHandler)

	port := ":8080"
	log.Printf("Galactic Exchange listening on %s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}