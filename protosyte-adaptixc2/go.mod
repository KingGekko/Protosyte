module protosyte-adaptixc2

go 1.24

require (
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	golang.org/x/time v0.6.0
	protosyte.io/mission-config v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace protosyte.io/mission-config => ../mission-config

