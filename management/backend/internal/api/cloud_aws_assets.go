package api

// AW-10: AWS asset inventory — EC2 instances, security groups, VPCs, S3
// buckets, RDS instances, Lambda functions, IAM users and roles. Uses the same
// stored shape as the GCP inventory so the existing UI renders it.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

func awsAsset(region, typ, id, label string, state string, labels map[string]string) GCPAsset {
	short := id
	if label != "" {
		short = label
	}
	loc := region
	if loc == "" {
		loc = "global"
	}
	return GCPAsset{Name: "aws:" + loc + ":" + typ + "/" + id, AssetType: typ, ShortName: short, Location: loc, State: state, Labels: labels}
}

func awsInstanceAssets(b []byte, region string) []GCPAsset {
	var r struct {
		Items []struct {
			ID    string `xml:"instanceId"`
			State string `xml:"instanceState>name"`
			Tags  []struct {
				K string `xml:"key"`
				V string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"reservationSet>item>instancesSet>item"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []GCPAsset
	for _, i := range r.Items {
		if i.State == "terminated" {
			continue
		}
		name := ""
		labels := map[string]string{}
		for _, t := range i.Tags {
			labels[t.K] = t.V
			if t.K == "Name" {
				name = t.V
			}
		}
		out = append(out, awsAsset(region, "ec2/Instance", i.ID, name, strings.ToUpper(i.State), labels))
	}
	return out
}

func awsSGAssets(b []byte, region string) []GCPAsset {
	var r struct {
		Items []struct {
			ID   string `xml:"groupId"`
			Name string `xml:"groupName"`
		} `xml:"securityGroupInfo>item"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []GCPAsset
	for _, g := range r.Items {
		out = append(out, awsAsset(region, "ec2/SecurityGroup", g.ID, g.Name, "ACTIVE", nil))
	}
	return out
}

func awsVPCAssets(b []byte, region string) []GCPAsset {
	var r struct {
		Items []struct {
			ID string `xml:"vpcId"`
		} `xml:"vpcSet>item"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []GCPAsset
	for _, v := range r.Items {
		out = append(out, awsAsset(region, "ec2/Vpc", v.ID, "", "ACTIVE", nil))
	}
	return out
}

func awsRDSAssets(b []byte, region string) []GCPAsset {
	var r struct {
		Items []struct {
			ID     string `xml:"DBInstanceIdentifier"`
			Status string `xml:"DBInstanceStatus"`
		} `xml:"DescribeDBInstancesResult>DBInstances>DBInstance"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []GCPAsset
	for _, d := range r.Items {
		out = append(out, awsAsset(region, "rds/DBInstance", d.ID, "", strings.ToUpper(d.Status), nil))
	}
	return out
}

func awsLambdaAssets(b []byte, region string) []GCPAsset {
	var r struct {
		Functions []struct {
			Name    string `json:"FunctionName"`
			Runtime string `json:"Runtime"`
		} `json:"Functions"`
	}
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []GCPAsset
	for _, f := range r.Functions {
		out = append(out, awsAsset(region, "lambda/Function", f.Name, "", "ACTIVE", map[string]string{"runtime": f.Runtime}))
	}
	return out
}

func awsS3Assets(names []string) []GCPAsset {
	var out []GCPAsset
	for _, n := range names {
		out = append(out, awsAsset("", "s3/Bucket", n, "", "ACTIVE", nil))
	}
	return out
}

func awsIAMAssets(b []byte, kind string) ([]GCPAsset, string) {
	var r struct {
		Users  []string `xml:"ListUsersResult>Users>member>UserName"`
		Roles  []string `xml:"ListRolesResult>Roles>member>RoleName"`
		Trunc  bool     `xml:"ListUsersResult>IsTruncated"`
		RTrunc bool     `xml:"ListRolesResult>IsTruncated"`
		Marker string   `xml:"ListUsersResult>Marker"`
		RMark  string   `xml:"ListRolesResult>Marker"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil, ""
	}
	var out []GCPAsset
	next := ""
	if kind == "user" {
		for _, n := range r.Users {
			out = append(out, awsAsset("", "iam/User", n, "", "ACTIVE", nil))
		}
		if r.Trunc {
			next = r.Marker
		}
	} else {
		for _, n := range r.Roles {
			out = append(out, awsAsset("", "iam/Role", n, "", "ACTIVE", nil))
		}
		if r.RTrunc {
			next = r.RMark
		}
	}
	return out, next
}

// RunAWSAssetInventory lists assets, diffs against the previous run (types that
// failed to list are carried forward and never reported as deleted) and stores
// the inventory at assets:aws:<id>.
func RunAWSAssetInventory(ctx context.Context, creds awsCreds, accountID string, connID int64, db *store.DB, logger *slog.Logger) (*GCPAssetInventory, error) {
	start := time.Now().UTC()
	inv := &GCPAssetInventory{ConnectorID: connID, ProjectID: accountID, ScannedAt: start, ByType: map[string]int{}}
	var mu sync.Mutex
	var all []GCPAsset
	skipped := map[string]bool{}
	fail := func(typ, why string) {
		mu.Lock()
		skipped[typ] = true
		inv.SkippedTypes = append(inv.SkippedTypes, typ+": "+why)
		mu.Unlock()
	}
	add := func(a []GCPAsset) {
		mu.Lock()
		all = append(all, a...)
		mu.Unlock()
	}

	iamCreds := creds
	iamCreds.Region = "us-east-1"
	for _, kind := range []string{"user", "role"} {
		typ := "iam/User"
		action := "ListUsers"
		if kind == "role" {
			typ, action = "iam/Role", "ListRoles"
		}
		marker := ""
		var collected []GCPAsset
		ok := true
		for page := 0; page < 20; page++ {
			form := "Action=" + action + "&Version=2010-05-08&MaxItems=1000"
			if marker != "" {
				form += "&Marker=" + url.QueryEscape(marker)
			}
			b, c, err := awsQueryCall(ctx, iamCreds, "iam", "iam.amazonaws.com", form)
			if err != nil || c != 200 {
				fail(typ, fmt.Sprintf("%s denied or failed", action))
				ok = false
				break
			}
			got, next := awsIAMAssets(b, kind)
			collected = append(collected, got...)
			if next == "" {
				break
			}
			marker = next
		}
		if ok {
			add(collected)
		}
	}
	if lb, lc, err := awsS3Get(ctx, iamCreds, "s3.amazonaws.com", "/"); err != nil || lc != 200 {
		fail("s3/Bucket", "ListBuckets denied or failed")
	} else {
		var bs struct {
			Names []string `xml:"Buckets>Bucket>Name"`
		}
		_ = xml.Unmarshal(lb, &bs)
		add(awsS3Assets(bs.Names))
	}

	regions := []string{creds.Region}
	if rb, rc, err := awsQueryCall(ctx, creds, "ec2", "ec2."+creds.Region+".amazonaws.com", "Action=DescribeRegions&Version=2016-11-15"); err == nil && rc == 200 {
		if rs := awsRegionsFromXML(rb); len(rs) > 0 {
			regions = rs
		}
	}
	if len(regions) > awsMaxRegions {
		regions = regions[:awsMaxRegions]
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for _, region := range regions {
		wg.Add(1)
		sem <- struct{}{}
		go func(region string) {
			defer wg.Done()
			defer func() { <-sem }()
			rc := creds
			rc.Region = region
			ec2 := "ec2." + region + ".amazonaws.com"
			type q struct {
				typ, form string
				parse     func([]byte, string) []GCPAsset
			}
			for _, x := range []q{
				{"ec2/Instance", "Action=DescribeInstances&Version=2016-11-15&MaxResults=1000", awsInstanceAssets},
				{"ec2/SecurityGroup", "Action=DescribeSecurityGroups&Version=2016-11-15", awsSGAssets},
				{"ec2/Vpc", "Action=DescribeVpcs&Version=2016-11-15", awsVPCAssets},
			} {
				b, c, err := awsQueryCall(ctx, rc, "ec2", ec2, x.form)
				if err != nil || c != 200 {
					fail(x.typ, region+": denied or failed")
					continue
				}
				add(x.parse(b, region))
			}
			if b, c, err := awsQueryCall(ctx, rc, "rds", "rds."+region+".amazonaws.com", "Action=DescribeDBInstances&Version=2014-10-31"); err != nil || c != 200 {
				fail("rds/DBInstance", region+": denied or failed")
			} else {
				add(awsRDSAssets(b, region))
			}
			if b, c, err := awsRESTGet(ctx, rc, "lambda", "lambda."+region+".amazonaws.com", "/2015-03-31/functions/?MaxItems=50"); err != nil || c != 200 {
				fail("lambda/Function", region+": denied or failed")
			} else {
				add(awsLambdaAssets(b, region))
			}
		}(region)
	}
	wg.Wait()

	for i := range all {
		all[i].FirstSeen, all[i].LastSeen = start, start
	}
	prev, _ := loadAWSInventory(ctx, db, connID)
	if prev != nil {
		kept := make([]GCPAsset, 0, len(prev.Assets))
		for _, a := range prev.Assets {
			if skipped[a.AssetType] {
				all = append(all, a) // carry forward; not diffed
			} else {
				kept = append(kept, a)
			}
		}
		cur := make([]GCPAsset, 0, len(all))
		for _, a := range all {
			if !skipped[a.AssetType] {
				cur = append(cur, a)
			}
		}
		inv.NewAssets, inv.DeletedAssets = computeDeltas(kept, cur)
		old := make(map[string]GCPAsset, len(prev.Assets))
		for _, a := range prev.Assets {
			old[a.Name] = a
		}
		for i, a := range all {
			if o, ok := old[a.Name]; ok {
				all[i].FirstSeen = o.FirstSeen
			}
		}
		if len(inv.DeletedAssets) > 0 && db != nil {
			fireAssetDeletionAlerts(ctx, db, inv.DeletedAssets, accountID, connID, logger)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	for _, a := range all {
		inv.ByType[a.AssetType]++
	}
	inv.Assets, inv.TotalAssets = all, len(all)
	sort.Strings(inv.SkippedTypes)
	if db != nil {
		if data, err := json.Marshal(inv); err == nil {
			if err := db.SetSetting(ctx, fmt.Sprintf("assets:aws:%d", connID), string(data)); err != nil {
				logger.Warn("aws asset inventory: failed to persist", "err", err)
			}
		}
	}
	return inv, nil
}

func loadAWSInventory(ctx context.Context, db *store.DB, connID int64) (*GCPAssetInventory, error) {
	if db == nil {
		return nil, nil
	}
	val, err := db.GetSetting(ctx, fmt.Sprintf("assets:aws:%d", connID))
	if err != nil || val == "" {
		return nil, nil
	}
	var inv GCPAssetInventory
	if err := json.Unmarshal([]byte(val), &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

func handleGetAWSAssets(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var id int64
		fmt.Sscan(r.PathValue("id"), &id)
		inv, err := loadAWSInventory(r.Context(), db, id)
		w.Header().Set("Content-Type", "application/json")
		if err != nil || inv == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"message": "No inventory yet — run a scan first", "assets": []struct{}{}})
			return
		}
		json.NewEncoder(w).Encode(inv)
	}
}

func handleRunAWSAssets(db *store.DB, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var id int64
		fmt.Sscan(r.PathValue("id"), &id)
		conn, err := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil {
			http.Error(w, "connector not found", 404)
			return
		}
		creds, cerr := resolveAWSCreds(r.Context(), conn.Credentials)
		if cerr != nil {
			writeJSON(w, 400, map[string]string{"error": cerr.Error()})
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			if _, err := RunAWSAssetInventory(ctx, creds, conn.AccountID, id, db, logger); err != nil {
				logger.Warn("aws asset inventory failed", "id", id, "err", err)
			}
		}()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "scanning"})
	}
}
