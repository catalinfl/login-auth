package misc

import (
	"fmt"
	"os"

	"github.com/catalinfl/login-auth/models"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var Database *gorm.DB

func ConnectDB() {

	err := godotenv.Load(".env")

	if err != nil {
		panic(err)
	}

	url := os.Getenv("DATABASE_URL")

	db, err := gorm.Open(postgres.Open(url), &gorm.Config{})

	if err != nil {
		panic(err)
	}

	db.AutoMigrate(&models.User{})

	fmt.Println("Database is working")

	Database = db
}
