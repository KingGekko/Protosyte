package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// MessageQueue handles encrypted storage of retrieved messages
type MessageQueue struct {
	db     *sql.DB
	key    []byte // AES-256 key derived from passphrase
	gcm    cipher.AEAD
	dbPath string
}

// QueuedMessage represents a message stored in the encrypted queue
type QueuedMessage struct {
	ID          int64
	MessageID   int
	ChatID      int64
	FileID      string
	Data        []byte
	RetrievedAt time.Time
	Processed   bool
	Metadata    map[string]interface{}
}

// NewMessageQueue creates a new encrypted message queue
func NewMessageQueue(dbPath string, passphrase string) (*MessageQueue, error) {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Derive AES key from passphrase
	hash := sha256.Sum256([]byte(passphrase))
	key := hash[:]

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Open SQLite database
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	queue := &MessageQueue{
		db:     db,
		key:    key,
		gcm:    gcm,
		dbPath: dbPath,
	}

	// Initialize schema
	if err := queue.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	return queue, nil
}

// initSchema creates the encrypted message queue table
func (mq *MessageQueue) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		telegram_message_id INTEGER NOT NULL,
		telegram_chat_id INTEGER NOT NULL,
		telegram_file_id TEXT,
		encrypted_data BLOB NOT NULL,
		nonce BLOB NOT NULL,
		retrieved_at DATETIME NOT NULL,
		processed BOOLEAN DEFAULT 0,
		metadata TEXT,
		INDEX idx_processed (processed),
		INDEX idx_retrieved_at (retrieved_at)
	);
	`
	_, err := mq.db.Exec(schema)
	return err
}

// Enqueue stores a Telegram message document in encrypted queue
func (mq *MessageQueue) Enqueue(msg *tgbotapi.Message, fileData []byte) error {
	// Prepare metadata
	metadata := map[string]interface{}{
		"message_id":   msg.MessageID,
		"chat_id":      msg.Chat.ID,
		"date":         msg.Date,
		"from_user_id": msg.From.ID,
		"has_document": msg.Document != nil,
	}
	
	if msg.Document != nil {
		metadata["file_name"] = msg.Document.FileName
		metadata["file_size"] = msg.Document.FileSize
		metadata["mime_type"] = msg.Document.MimeType
	}

	metadataJSON, _ := json.Marshal(metadata)

	// Encrypt file data
	nonce := make([]byte, mq.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	encryptedData := mq.gcm.Seal(nil, nonce, fileData, nil)

	// Store in database
	query := `
		INSERT INTO messages 
		(telegram_message_id, telegram_chat_id, telegram_file_id, encrypted_data, nonce, retrieved_at, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	fileID := ""
	if msg.Document != nil {
		fileID = msg.Document.FileID
	}

	_, err := mq.db.Exec(query,
		msg.MessageID,
		msg.Chat.ID,
		fileID,
		encryptedData,
		nonce,
		time.Now(),
		string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to enqueue message: %w", err)
	}

	log.Printf("[QUEUE] Enqueued message %d (encrypted, %d bytes)", msg.MessageID, len(encryptedData))
	return nil
}

// Dequeue retrieves and decrypts unprocessed messages
func (mq *MessageQueue) Dequeue(limit int) ([]*QueuedMessage, error) {
	query := `
		SELECT id, telegram_message_id, telegram_chat_id, telegram_file_id, 
		       encrypted_data, nonce, retrieved_at, processed, metadata
		FROM messages
		WHERE processed = 0
		ORDER BY retrieved_at ASC
		LIMIT ?
	`

	rows, err := mq.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages: %w", err)
	}
	defer rows.Close()

	var messages []*QueuedMessage

	for rows.Next() {
		var msg QueuedMessage
		var encryptedData, nonce []byte
		var metadataJSON string

		err := rows.Scan(
			&msg.ID,
			&msg.MessageID,
			&msg.ChatID,
			&msg.FileID,
			&encryptedData,
			&nonce,
			&msg.RetrievedAt,
			&msg.Processed,
			&metadataJSON,
		)
		if err != nil {
			log.Printf("[QUEUE] Failed to scan message: %v", err)
			continue
		}

		// Decrypt data
		decryptedData, err := mq.gcm.Open(nil, nonce, encryptedData, nil)
		if err != nil {
			log.Printf("[QUEUE] Failed to decrypt message %d: %v", msg.ID, err)
			continue
		}

		msg.Data = decryptedData

		// Parse metadata
		if metadataJSON != "" {
			json.Unmarshal([]byte(metadataJSON), &msg.Metadata)
		}

		messages = append(messages, &msg)
	}

	return messages, nil
}

// MarkProcessed marks a message as processed
func (mq *MessageQueue) MarkProcessed(id int64) error {
	_, err := mq.db.Exec("UPDATE messages SET processed = 1 WHERE id = ?", id)
	return err
}

// GetUnprocessedCount returns the number of unprocessed messages
func (mq *MessageQueue) GetUnprocessedCount() (int, error) {
	var count int
	err := mq.db.QueryRow("SELECT COUNT(*) FROM messages WHERE processed = 0").Scan(&count)
	return count, err
}

// CleanupOldProcessed removes processed messages older than specified duration
func (mq *MessageQueue) CleanupOldProcessed(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	_, err := mq.db.Exec("DELETE FROM messages WHERE processed = 1 AND retrieved_at < ?", cutoff)
	return err
}

// Close closes the database connection
func (mq *MessageQueue) Close() error {
	return mq.db.Close()
}

