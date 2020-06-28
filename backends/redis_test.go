package backends

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestRedis(t *testing.T) {

	//Initialize Redis with some test values.
	authOpts := make(map[string]string)
	authOpts["redis_host"] = "localhost"
	authOpts["redis_port"] = "6379"
	authOpts["redis_db"] = "2"
	authOpts["redis_password"] = ""

	ctx := context.Background()

	testRedis(ctx, t, authOpts)
}

func TestRedisCluster(t *testing.T) {

	//Initialize Redis with some test values.
	authOpts := make(map[string]string)
	authOpts["redis_mode"] = "cluster"
	authOpts["redis_cluster_addresses"] = "localhost:7000,localhost:7001,localhost:7002"
	ctx := context.Background()

	testRedis(ctx, t, authOpts)

}

func testRedis(ctx context.Context, t *testing.T, authOpts map[string]string) {
	redis, err := NewRedis(authOpts, log.DebugLevel)
	assert.Nil(t, err)

	//Empty db
	redis.conn.FlushDB(context.Background())

	//Insert a user to test auth
	username := "test"
	userPass := "testpw"
	//Hash generated by the pw utility
	userPassHash := "PBKDF2$sha512$100000$os24lcPr9cJt2QDVWssblQ==$BK1BQ2wbwU1zNxv3Ml3wLuu5//hPop3/LvaPYjjCwdBvnpwusnukJPpcXQzyyjOlZdieXTx6sXAcX4WnZRZZnw=="
	redis.conn.Set(ctx, username, userPassHash, 0)

	authenticated := redis.GetUser(username, userPass, "")
	assert.True(t, authenticated)

	authenticated = redis.GetUser(username, "wrong_password", "")
	assert.False(t, authenticated)

	redis.conn.Set(ctx, username+":su", "true", 0)
	superuser := redis.GetSuperuser(username)
	assert.True(t, superuser)

	redis.disableSuperuser = true
	superuser = redis.GetSuperuser(username)
	assert.False(t, superuser)

	redis.disableSuperuser = false

	//Now create some acls and test topics
	strictAcl := "test/topic/1"
	singleLevelAcl := "test/topic/+"
	hierarchyAcl := "test/#"

	userPattern := "test/%u"
	clientPattern := "test/%c"
	clientID := "test_client"
	writeAcl := "write/test"
	readWriteAcl := "test/readwrite/1"
	commonTopic := "hashing/test/topic"

	redis.conn.SAdd(ctx, username+":racls", strictAcl)

	testTopic1 := `test/topic/1`
	testTopic2 := `test/topic/2`

	tt1 := redis.CheckAcl(username, testTopic1, clientID, MOSQ_ACL_READ)
	tt2 := redis.CheckAcl(username, testTopic2, clientID, MOSQ_ACL_READ)

	assert.True(t, tt1)
	assert.False(t, tt2)

	tt1 = redis.CheckAcl(username, singleLevelAcl, clientID, MOSQ_ACL_READ)
	tt2 = redis.CheckAcl(username, hierarchyAcl, clientID, MOSQ_ACL_READ)

	assert.False(t, tt1)
	assert.False(t, tt2)

	//Now check against hashing patterns.
	redis.conn.SAdd(ctx, "hashing:racls", userPattern)
	tt1 = redis.CheckAcl(username, "test/test", clientID, MOSQ_ACL_READ)
	assert.True(t, tt1)

	redis.conn.SAdd(ctx, "hashing:racls", clientPattern)

	tt1 = redis.CheckAcl(username, "test/test_client", clientID, MOSQ_ACL_READ)
	assert.True(t, tt1)

	redis.conn.SAdd(ctx, username+":racls", singleLevelAcl)
	tt1 = redis.CheckAcl(username, "test/topic/whatever", clientID, MOSQ_ACL_READ)
	assert.True(t, tt1)

	redis.conn.SAdd(ctx, username+":racls", hierarchyAcl)

	tt1 = redis.CheckAcl(username, "test/what/ever", clientID, MOSQ_ACL_READ)
	assert.True(t, tt1)

	tt1 = redis.CheckAcl(username, "test/test", clientID, MOSQ_ACL_WRITE)
	assert.False(t, tt1)

	//Add a write only acl and check for subscription.
	redis.conn.SAdd(ctx, username+":wacls", writeAcl)
	tt1 = redis.CheckAcl(username, writeAcl, clientID, MOSQ_ACL_READ)
	tt2 = redis.CheckAcl(username, writeAcl, clientID, MOSQ_ACL_WRITE)
	assert.False(t, tt1)
	assert.True(t, tt2)

	//Add a readwrite acl and check for subscription.
	redis.conn.SAdd(ctx, username+":rwacls", readWriteAcl)
	tt1 = redis.CheckAcl(username, readWriteAcl, clientID, MOSQ_ACL_READ)
	tt2 = redis.CheckAcl(username, readWriteAcl, clientID, MOSQ_ACL_WRITE)
	assert.True(t, tt1)
	assert.True(t, tt2)

	//Now add a hashing read acl to check against.
	redis.conn.SAdd(ctx, "hashing:racls", commonTopic)
	tt1 = redis.CheckAcl("unknown", commonTopic, clientID, MOSQ_ACL_READ)
	assert.True(t, tt1)

	// Assert that only read works for a given topic in racls.
	topic := "readable/topic"
	redis.conn.SAdd(ctx, username+":racls", topic)
	tt1 = redis.CheckAcl(username, topic, clientID, MOSQ_ACL_SUBSCRIBE)
	tt2 = redis.CheckAcl(username, topic, clientID, MOSQ_ACL_READ)
	assert.False(t, tt1)
	assert.True(t, tt2)

	// Assert that only subscribe works for a given topic in sacls.
	topic = "subscribable/topic"
	redis.conn.SAdd(ctx, username+":sacls", topic)
	tt1 = redis.CheckAcl(username, topic, clientID, MOSQ_ACL_SUBSCRIBE)
	tt2 = redis.CheckAcl(username, topic, clientID, MOSQ_ACL_READ)
	assert.True(t, tt1)
	assert.False(t, tt2)

	topic = "commonsubscribable/topic"
	redis.conn.SAdd(ctx, "hashing:sacls", topic)
	tt1 = redis.CheckAcl(username, topic, clientID, MOSQ_ACL_SUBSCRIBE)
	tt2 = redis.CheckAcl(username, topic, clientID, MOSQ_ACL_READ)
	assert.True(t, tt1)
	assert.False(t, tt2)

	//Empty db
	redis.conn.FlushDB(context.Background())
	redis.Halt()
}
