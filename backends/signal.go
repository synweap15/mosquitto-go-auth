package backends

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/iegomez/mosquitto-go-auth/common"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/snksoft/crc"
)

type Signal struct {
	mysql       Mysql
	UserPrefix  string
	UserQuery   string
	InsertQuery string
}

type User struct {
	Username     string
	PasswordHash string
	IsActive     bool
	IsAdmin      bool
}

// parsed parameters and
var mysql Mysql

func CRC32Hash(input string) string {
	params := crc.Parameters{
		Width:      32,
		Polynomial: 0x04C11DB7,
		Init:       0xFFFFFFFF,
		ReflectIn:  false,
		ReflectOut: false,
		FinalXor:   0x00000000,
	}

	value := crc.CalculateCRC(&params, []byte(input))
	return strconv.FormatUint(value, 10)
}

func NewSignal(authOpts map[string]string, logLevel log.Level) (Signal, error) {
	//Initialize your plugin with the necessary options
	log.SetLevel(logLevel)

	var signal = Signal{}

	signalOk := true
	missingOptions := ""

	if userPrefix, ok := authOpts["signal_userprefix"]; ok {
		signal.UserPrefix = userPrefix
	} else {
		signalOk = false
		missingOptions += " signal_userprefix"
	}

	if userQuery, ok := authOpts["signal_userquery"]; ok {
		signal.UserQuery = userQuery
	} else {
		signalOk = false
		missingOptions += " signal_userquery"
	}

	if insertQuery, ok := authOpts["signal_insertquery"]; ok {
		signal.InsertQuery = insertQuery
	} else {
		signalOk = false
		missingOptions += " signal_insertquery"
	}

	//Exit if any mandatory option is missing.
	if !signalOk {
		return signal, errors.Errorf("signal backend error: missing options: %s", missingOptions)
	}

	var err error
	mysql, err = NewMysql(authOpts, logLevel)
	signal.mysql = mysql
	if err != nil {
		return signal, errors.Errorf("couldn't initialize signal plugin: %s", err)
	}

	return signal, nil
}

func (o Signal) GetUser(username, password, clientid string) bool {
	if len(username) <= len(o.UserPrefix) {
		log.Infof("Username is too short: %s", username)
		return false
	}

	if !strings.HasPrefix(username, o.UserPrefix) {
		log.Infof("Username does not have the required prefix: '%s': %s", o.UserPrefix, username)
		return false
	}

	id := username[5:]
	if CRC32Hash(id) != password {
		log.Infof("Incorrect username and password for %s", username)
		return false
	}

	log.Infof("Correct username and password for %s", username)

	// check if user exists in the database
	var count sql.NullInt64
	err := mysql.DB.Get(&count, o.UserQuery, username)
	if err != nil || !count.Valid {
		log.Errorf("DB Get error: %s", err)
		return false
	}

	// if does exist, return false, let other backends handle it
	if count.Int64 > 0 {
		log.Info("User already exists, releasing for other backends")
		return false
	}

	passwordHash, err := common.Hash(password, 16, 25000, "sha512", common.Base64, 64)
	if err != nil {
		log.Errorf("Password hash failed")
		return false
	}

	// if does not exist, insert, return true
	user := User{
		Username:     username,
		PasswordHash: passwordHash,
		IsActive:     true,
		IsAdmin:      false,
	}

	stmt, err := mysql.DB.PrepareNamed(o.InsertQuery)
	if err != nil {
		log.Errorf("Prepared statement error: %s", err)
		return false
	}

	_, err = stmt.Exec(user)
	if err != nil {
		log.Errorf("Prepared statement exec error: %s", err)
		return false
	}

	return true
}

func (o Signal) GetSuperuser(username string) bool {
	return false
}

func (o Signal) CheckAcl(username, topic, clientid string, acc int32) bool {
	return false
}

func (o Signal) GetName() string {
	return "signal"
}

func (o Signal) Halt() {
	o.mysql.Halt()
}
