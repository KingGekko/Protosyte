package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"protosyte.io/mission-config"
)

type Retriever struct {
	queue *MessageQueue
	store string
}

type QueuedMessage struct {
	ID          int64
	MessageID   int
	ChatID      int64
	FileID      string
	Data        []byte
	RetrievedAt time.Time
	Processed   bool
}

type MessageQueue struct {
	db     *sql.DB
	key    []byte
	gcm    cipher.AEAD
	dbPath string
}

func NewRetriever(queueDBPath string, passphrase string) (*Retriever, error) {
	// Try to load mission config for store path
	missionConfig, _ := mission.LoadMissionConfig("")
	store := "/tmp/rig_store"
	if missionConfig != nil && missionConfig.Analysis.VMIP != "" {
		// Could use mission config for custom store path
	}
	os.MkdirAll(store, 0755)

	// Open the same encrypted queue database that Broadcast Engine uses
	queue, err := openQueueDB(queueDBPath, passphrase)
	if err != nil {
		return nil, err
	}

	return &Retriever{
		queue: queue,
		store: store,
	}, nil
}

func openQueueDB(dbPath string, passphrase string) (*MessageQueue, error) {
	// Use same encryption logic as Broadcast Engine
	// Derive AES key from passphrase
	hash := sha256.Sum256([]byte(passphrase))
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}

	return &MessageQueue{
		db:     db,
		key:    key,
		gcm:    gcm,
		dbPath: dbPath,
	}, nil
}

func (mq *MessageQueue) Dequeue(limit int) ([]*QueuedMessage, error) {
	query := `
		SELECT id, telegram_message_id, telegram_chat_id, telegram_file_id, 
		       encrypted_data, nonce, retrieved_at, processed
		FROM messages
		WHERE processed = 0
		ORDER BY retrieved_at ASC
		LIMIT ?
	`

	rows, err := mq.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*QueuedMessage

	for rows.Next() {
		var msg QueuedMessage
		var encryptedData, nonce []byte

		err := rows.Scan(
			&msg.ID,
			&msg.MessageID,
			&msg.ChatID,
			&msg.FileID,
			&encryptedData,
			&nonce,
			&msg.RetrievedAt,
			&msg.Processed,
		)
		if err != nil {
			log.Printf("[RET] Failed to scan message: %v", err)
			continue
		}

		// Decrypt data
		decryptedData, err := mq.gcm.Open(nil, nonce, encryptedData, nil)
		if err != nil {
			log.Printf("[RET] Failed to decrypt message %d: %v", msg.ID, err)
			continue
		}

		msg.Data = decryptedData
		messages = append(messages, &msg)
	}

	return messages, nil
}

func (mq *MessageQueue) MarkProcessed(id int64) error {
	_, err := mq.db.Exec("UPDATE messages SET processed = 1 WHERE id = ?", id)
	return err
}

func (r *Retriever) Retrieve() error {
	// Query encrypted queue for unprocessed messages
	messages, err := r.queue.Dequeue(100)
	if err != nil {
		return err
	}

	for _, msg := range messages {
		// Save decrypted payload
		filePath := filepath.Join(r.store, msg.FileID)
		if err := os.WriteFile(filePath, msg.Data, 0600); err != nil {
			log.Printf("[RET] Failed to save payload: %v", err)
			continue
		}

		log.Printf("[RET] Retrieved message %d: %s (%d bytes)", msg.ID, filePath, len(msg.Data))

		// Mark as processed
		if err := r.queue.MarkProcessed(msg.ID); err != nil {
			log.Printf("[RET] Failed to mark processed: %v", err)
		}
	}

	return nil
}
