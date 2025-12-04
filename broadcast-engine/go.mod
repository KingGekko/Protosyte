module protosyte.io/broadcast-engine

go 1.24

require (
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1
	github.com/mattn/go-sqlite3 v1.14.32
	protosyte.io/mission-config v0.0.0
)

require gopkg.in/yaml.v3 v3.0.1 // indirect

replace protosyte.io/mission-config => ../mission-config
