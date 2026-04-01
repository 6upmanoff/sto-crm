package main

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

var db *sql.DB

func initDB() {
	var err error

	connStr := "user=6upmanoff dbname=sto_crm sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Ошибка подключения к БД: ", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("База данных не отвечает: ", err)
	}

	log.Println("База данных успешно подключена")
}
