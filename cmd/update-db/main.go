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
	trivydb.OpenDatabase(TRIVY_DB)
	chndb := vdb.NewVulnDB()
	chndb.OpenDatabase(CHN_DB)
	defer func() {
		fmt.Println("close connect")
		if trivydb != nil {
			trivydb.CloseDatabase()
		}
		if chndb != nil {
			chndb.CloseDatabase()
		}
	}()
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
						trivydb.SaveVuln("vulnerability", string(k), mb)
					}
				}

			}
			return nil
		})

		return nil
	})

}
