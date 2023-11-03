package driver

import (
	"database/sql"
	"time"
	_ "github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"


)

// DB holds the database connection pool
type DB struct {
	SQL *sql.DB
}

var dbConn = &DB{}

const maxOpenDbConn = 10
const MaxIdleDbConn = 5
const MaxDbLifetime = 5 * time.Minute

// creates database pool for postgres
func ConnectSQL(dsn string) (*DB, error) {
	d, err := NewDatabase(dsn)
	if err != nil {
		panic(err)
	}
	d.SetMaxOpenConns(maxOpenDbConn)
	d.SetMaxIdleConns(MaxIdleDbConn)
	d.SetConnMaxLifetime(MaxDbLifetime)
	dbConn.SQL = d
	err = testDB(d)
	if err != nil {
		return nil, err
	}
	return dbConn, nil

}

// ping db
func testDB(d *sql.DB) error {
	err := d.Ping()
	if err != nil {
		return err
	}
	return nil
}

// open new db
func NewDatabase(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
