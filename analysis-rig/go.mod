module protosyte.io/analysis-rig

go 1.24

require (
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1
	golang.org/x/crypto v0.24.0
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.30.0
	protosyte.io/mission-config v0.0.0
)

replace protosyte.io/mission-config => ../mission-config

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	golang.org/x/text v0.20.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
