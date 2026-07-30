module github.com/DarrenMannuela/KMA-auth

go 1.25

require (
	github.com/gin-gonic/gin v1.10.0
	golang.org/x/crypto v0.28.0
	golang.org/x/time v0.7.0
	gorm.io/driver/sqlite v1.5.6
	gorm.io/gorm v1.25.12
)

// Run `go mod tidy` after copying this module into your environment —
// it will resolve the exact patch versions and fill in the indirect
// dependency block (gin's own deps: json-iterator, validator, etc).
