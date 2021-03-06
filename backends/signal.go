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
	TOPIC_PERMISSION_READ                 = 1
	TOPIC_PERMISSION_WRITE                = 2
	TOPIC_PERMISSION_READ_WRITE           = 3
	TOPIC_PERMISSION_SUBSCRIBE            = 4
	TOPIC_PERMISSION_READ_SUBSCRIBE       = 5
	TOPIC_PERMISSION_WRITE_SUBSCRIBE      = 6
	TOPIC_PERMISSION_READ_WRITE_SUBSCRIBE = 7
)

const TOPIC_PERMISSIONS_DEFAULT_KEY = "_default_"

type TopicPermissions map[string]int

var topicPermissions = TopicPermissions{
	"READ":                 TOPIC_PERMISSION_READ,
	"WRITE":                TOPIC_PERMISSION_WRITE,
	"READ_WRITE":           TOPIC_PERMISSION_READ_WRITE,
	"SUBSCRIBE":            TOPIC_PERMISSION_SUBSCRIBE,
	"READ_SUBSCRIBE":       TOPIC_PERMISSION_READ_SUBSCRIBE,
	"WRITE_SUBSCRIBE":      TOPIC_PERMISSION_WRITE_SUBSCRIBE,
	"READ_WRITE_SUBSCRIBE": TOPIC_PERMISSION_READ_WRITE_SUBSCRIBE,
}

type TopicACLs map[string]int
type PrefixToTopicACLs map[string]TopicACLs

type Signal struct {
	mysql          Mysql
	UserPrefix     string
	UserQuery      string
	InsertQuery    string
	InsertACLQuery string

	PrefixToTopicACLs PrefixToTopicACLs
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

	// aclRolesAll, okRoles := authOpts["signal_acl_roles"]
	aclRolesPrefixAll, okRolesPrefix := authOpts["signal_acl_roles_prefix"]
	aclTopicsAll, okTopics := authOpts["signal_acl_topics"]
	aclPermissionsAll, okPermissions := authOpts["signal_acl_permissions"]

	// todo: make sure input is sane
	if okRolesPrefix && okTopics && okPermissions {
		aclRolesPrefix := strings.Split(aclRolesPrefixAll, ";")
		aclTopics := strings.Split(aclTopicsAll, ";")
		aclPermissions := strings.Split(aclPermissionsAll, ";")

		signal.PrefixToTopicACLs = PrefixToTopicACLs{}

		for index, prefix := range aclRolesPrefix {
			aclTopicsList := strings.Split(aclTopics[index], ",")
			aclPermissionsList := strings.Split(aclPermissions[index], ",")
			if len(aclTopicsList) != len(aclPermissionsList) {
				signalOk = false
				missingOptions += " signal_acl_topics and signal_acl_permissions param count"
			}

			topicACLs := TopicACLs{}
			for i, _ := range aclTopicsList {
				topicACLs[aclTopicsList[i]] = topicPermissions[aclPermissionsList[i]]
			}
			signal.PrefixToTopicACLs[prefix] = topicACLs
		}
	} else {
		signalOk = false
		missingOptions += " signal_acl_roles"
	}

	if _, ok := signal.PrefixToTopicACLs[TOPIC_PERMISSIONS_DEFAULT_KEY]; !ok {
		signalOk = false
		missingOptions += " default_key"
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

func (o Signal) GetTopicACLsByUsername(username string) (TopicACLs, error) {
	var correctTopic TopicACLs
	if defaultACLs, ok := o.PrefixToTopicACLs[TOPIC_PERMISSIONS_DEFAULT_KEY]; ok {
		correctTopic = defaultACLs
	} else {
		return nil, errors.Errorf("There's no default TopicACL!")
	}

	for topicPrefix, topicACL := range o.PrefixToTopicACLs {
		if strings.HasPrefix(username, o.UserPrefix+topicPrefix) {
			correctTopic = topicACL
		}
	}

	return correctTopic, nil
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

	topicACLs, err := o.GetTopicACLsByUsername(username)
	if err != nil {
		log.Errorf("GetTopicACLsByUsername error: %s", err)
	}

	for topic, permission := range topicACLs {
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
