package vdb

import (
	"encoding/json"
	"errors"
	"fmt"

	"go.etcd.io/bbolt"
)

var dbpath string = "cn_vuln.db"

const BUCKET_NAME = "CN_VULN_DB"

type VulnDB struct {
	opened bool
	Dbpath string
	DB     *bbolt.DB
}

func (v *VulnDB) OpenDatabase(dbp string) error {
	if v.opened {
		return nil
	}

	if len(dbp) == 0 {
		dbp = dbpath
	}
	db, err := bbolt.Open(dbp, 0600, nil)
	if err == nil {
		v.opened = true
		v.DB = db
	} else {
		v.CloseDatabase()
	}

	return err
}

func (v *VulnDB) CloseDatabase() error {
	if v.DB != nil {
		err := v.DB.Close()
		v.DB = nil
		v.opened = false
		return err
	} else {
		v.opened = false
	}
	return nil
}

func NewVulnDB() *VulnDB {
	v := VulnDB{}
	return &v

}

type Cve struct {
	Cveid string
	Title string
	Desc  string
}

func (v *VulnDB) GetVulnByCveId(bucket string, id string) map[string]interface{} {
	m := make(map[string]interface{}, 0)
	v.DB.View(func(tx *bbolt.Tx) error {

		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return fmt.Errorf("bucket '%s' not exist", bucket)
		}
		cbype := b.Get([]byte(id))
		if len(cbype) > 0 {

			if err := json.Unmarshal(cbype, &m); err == nil {
				return nil
			} else {
				return err
			}
		}
		return nil
	})
	return m
}

func (v *VulnDB) SaveVuln(bucket string, key string, vuln []byte) error {

	if len(bucket) == 0 || len(vuln) == 0 {
		return errors.New("bucket or vuln can be not empty")
	}

	return v.DB.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(BUCKET_NAME)); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucket))
		return b.Put([]byte(key), vuln)
	})

}
