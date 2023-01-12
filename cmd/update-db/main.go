package main

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/trivy-db/pkg/vdb"
	"go.etcd.io/bbolt"
)

func init() {

}

const TRIVY_DB string = "cache/db/trivy.db"
const CHN_DB string = "cn_vuln.db"

func main() {

	trivydb := vdb.NewVulnDB()
	if err := trivydb.OpenDatabase(TRIVY_DB); err != nil {
		fmt.Println(err.Error())
	}
	chndb := vdb.NewVulnDB()
	if err := chndb.OpenDatabase(CHN_DB); err != nil {
		fmt.Println(err.Error())
	}
	defer func() {
		fmt.Println("close connect")
		if trivydb != nil {
			trivydb.CloseDatabase()
		}
		if chndb != nil {
			chndb.CloseDatabase()
		}
	}()
	noMatch := 0
	totalChange := 0
	chndb.DB.View(func(tx *bbolt.Tx) error {
		buckets := tx.Bucket([]byte(vdb.BUCKET_NAME))
		buckets.ForEach(func(k, v []byte) error {
			cve := &vdb.Cve{}
			json.Unmarshal(v, cve)
			m := trivydb.GetVulnByCveId("vulnerability", string(k))
			changed := false

			if len(m) > 0 {
				if title, ok := m["Title"].(string); ok {
					if len(cve.Title) > 0 && len(title) > 0 {
						m["Title"] = cve.Title
						changed = true
					}
				}
				if desc, ok := m["Description"].(string); ok {
					if len(cve.Desc) > 0 && len(desc) > 0 {
						m["Description"] = cve.Desc
						changed = true
					}
				}
				if changed {
					if mb, err := json.Marshal(&m); err == nil {
						fmt.Println(fmt.Sprintf("update key %s", string(k)))
						totalChange++
						trivydb.SaveVuln("vulnerability", string(k), mb)
					}
				} else {
					noMatch++
				}

			}
			return nil
		})
		fmt.Printf("update total cve count: %d", totalChange)
		fmt.Printf("Not match cve count: %d", noMatch)
		return nil
	})

}
