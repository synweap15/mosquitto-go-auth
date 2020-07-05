package backends

import (
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/iegomez/mosquitto-go-auth/common"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/snksoft/crc"
)

const (
	TOPIC_PERMISSION_READ      = 1
	TOPIC_PERMISSION_WRITE     = 2
	TOPIC_PERMISSION_READWRITE = 3
)

type TopicPermissions map[string]int

var topicPermissions = TopicPermissions{
	"READ":      TOPIC_PERMISSION_READ,
	"WRITE":     TOPIC_PERMISSION_WRITE,
	"READWRITE": TOPIC_PERMISSION_READWRITE,
}

type TopicACLs map[string]int

type Signal struct {
	mysql          Mysql
	UserPrefix     string
	UserQuery      string
	InsertQuery    string
	InsertACLQuery string

	TopicACLs TopicACLs
}

type User struct {
	Username     string
	PasswordHash string
	IsActive     bool
	IsAdmin      bool
}

type UserACL struct {
	BrokerUserId int64
	Topic        string
	ReadWrite    int
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

	if insertACLQuery, ok := authOpts["signal_insertaclquery"]; ok {
		signal.InsertACLQuery = insertACLQuery
	} else {
		signalOk = false
		missingOptions += " signal_insertaclquery"
	}

	aclTopics, okTopics := authOpts["signal_acl_topics"]
	aclPermissions, okPermissions := authOpts["signal_acl_permissions"]

	// todo: make sure input is sane
	if okTopics && okPermissions {
		aclTopicsList := strings.Split(aclTopics, ",")
		aclPermissionsList := strings.Split(aclPermissions, ",")
		if len(aclTopicsList) != len(aclPermissionsList) {
			signalOk = false
			missingOptions += " signal_acl_topics and signal_acl_permissions param count"
		}

		topicACLs := TopicACLs{}
		for i, _ := range aclTopicsList {
			topicACLs[aclTopicsList[i]] = topicPermissions[aclPermissionsList[i]]
		}

		signal.TopicACLs = topicACLs

	} else {
		signalOk = false
		if !okTopics {
			missingOptions += " signal_acl_topics"
		}
		if !okPermissions {
			missingOptions += " signal_acl_permissions"
		}
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
	// Make sure there are no disallowed characters in the ID
	matched, err := regexp.Match(`([a-zA-Z0-9 \-]+)`, []byte(id))
	if err != nil {
		log.Errorf("Regex: %s", err)
	}
	if !matched {
		log.Infof("Regex: username %s does not fit the matching criteria", id)
		return false
	}
	if CRC32Hash(id) != password {
		log.Infof("Incorrect username and password for %s", username)
		return false
	}

	log.Infof("Correct username and password for %s", username)

	// check if user exists in the database
	var userIdResult sql.NullInt64
	err = mysql.DB.Get(&userIdResult, o.UserQuery, username)
	if err == nil {
		// User already exists, return false, let other backends handle it
		log.Info("User does exists, releasing for other backends")
		return false
	} else if err == sql.ErrNoRows {
		// if does not exist exist
		log.Info("User does not exists, creating..")
	} else {
		// Some generic error
		log.Errorf("DB Get error: %s", err)
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

	// todo: this should be in a transaction
	userInsertStatement, err := mysql.DB.PrepareNamed(o.InsertQuery)
	if err != nil {
		log.Errorf("Prepared statement (InsertQuery) error: %s", err)
		return false
	}

	_, err = userInsertStatement.Exec(user)
	if err != nil {
		log.Errorf("Prepared statement (InsertQuery) exec error: %s", err)
		return false
	}

	// get User ID

	err = mysql.DB.Get(&userIdResult, o.UserQuery, username)
	if err != nil {
		log.Errorf("DB Get error: %s", err)
		return false
	}

	userId := userIdResult.Int64

	// insert ACL
	// readings/<id>/# - write
	// debug/<id>/# - write
	// control/<id>/# - read

	aclInsertStatement, err := mysql.DB.PrepareNamed(o.InsertACLQuery)
	if err != nil {
		log.Errorf("Prepared statement (InsertACLQuery) error: %s", err)
		return false
	}

	for topic, permission := range o.TopicACLs {
		if strings.Contains(topic, "%s") {
			topic = fmt.Sprintf(topic, id)
		}
		userAcl := UserACL{
			BrokerUserId: userId,
			Topic:        topic,
			ReadWrite:    permission,
		}
		_, err = aclInsertStatement.Exec(userAcl)
		if err != nil {
			log.Errorf("Prepared statement (InsertACLQuery) exec error: %s", err)
			return false
		}
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
