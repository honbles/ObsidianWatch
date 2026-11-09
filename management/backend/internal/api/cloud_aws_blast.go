package api

// cloud_aws_blast.go — AWS blast radius (CR-01 / AW-10).
//
// Graph: internet → (open security group) → EC2 instance → (instance profile)
// → IAM role → privilege. Buckets that CSPM flagged are added as nodes.
// Privilege is judged from attached managed policy names and customer-managed
// or inline policy documents; AWS-managed policy contents are not fetched, so
// only well-known broad ones (AdministratorAccess, PowerUserAccess, *FullAccess,
// IAMFullAccess) are recognised.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

type awsBlastRole struct {
	Name, ARN string
	Risk      string
	Why       string
	Profiles  []string // instance profile ARNs
}

type awsBlastInstance struct {
	ID, Region, Name, PublicIP, ProfileARN string
	SGs                                    []string
}

type awsBlastSG struct {
	ID, Region     string
	OpenWorld      bool
	OpenSensitive  bool
	OpenPortsLabel string
}

type awsBlastLambda struct{ Name, Region, RoleARN string }

type awsBlastDB struct {
	ID, Region, Engine string
	Public             bool
	SGs                []string
}

type awsBlastInput struct {
	Lambdas   []awsBlastLambda
	DBs       []awsBlastDB
	Roles     []awsBlastRole
	Users     []awsBlastRole // same shape; Profiles unused
	Instances []awsBlastInstance
	SGs       []awsBlastSG
	CSPM      *CSPMResult
}

var awsSensitivePorts = map[int]bool{22: true, 3389: true, 3306: true, 5432: true, 1433: true, 6379: true, 27017: true, 9200: true, 445: true, 23: true}

// awsManagedPolicyRisk classifies an attached managed policy by name.
func awsManagedPolicyRisk(name string) string {
	switch {
	case name == "AdministratorAccess":
		return "critical"
	case name == "IAMFullAccess", name == "PowerUserAccess":
		return "critical"
	case strings.HasSuffix(name, "FullAccess"), strings.Contains(name, "Admin"):
		return "high"
	}
	return "none"
}

func awsBlastEntities(b []byte) (roles, users []awsBlastRole, local map[string]string) {
	var d struct {
		Roles []struct {
			Name     string `xml:"RoleName"`
			ARN      string `xml:"Arn"`
			Attached []struct {
				N string `xml:"PolicyName"`
			} `xml:"AttachedManagedPolicies>member"`
			Inline []struct {
				N string `xml:"PolicyName"`
				D string `xml:"PolicyDocument"`
			} `xml:"RolePolicyList>member"`
			Profiles []string `xml:"InstanceProfileList>member>Arn"`
		} `xml:"GetAccountAuthorizationDetailsResult>RoleDetailList>member"`
		Users []struct {
			Name     string `xml:"UserName"`
			ARN      string `xml:"Arn"`
			Attached []struct {
				N string `xml:"PolicyName"`
			} `xml:"AttachedManagedPolicies>member"`
			Inline []struct {
				N string `xml:"PolicyName"`
				D string `xml:"PolicyDocument"`
			} `xml:"UserPolicyList>member"`
		} `xml:"GetAccountAuthorizationDetailsResult>UserDetailList>member"`
		Policies []struct {
			Name     string `xml:"PolicyName"`
			Versions []struct {
				Doc     string `xml:"Document"`
				Default bool   `xml:"IsDefaultVersion"`
			} `xml:"PolicyVersionList>member"`
		} `xml:"GetAccountAuthorizationDetailsResult>Policies>member"`
	}
	local = map[string]string{}
	if xml.Unmarshal(b, &d) != nil {
		return
	}
	for _, p := range d.Policies {
		for _, v := range p.Versions {
			if v.Default {
				doc, err := url.QueryUnescape(v.Doc)
				if err != nil {
					doc = v.Doc
				}
				if awsPolicyAllowsAll(doc) {
					local[p.Name] = "critical"
				}
			}
		}
	}
	judge := func(attached []string, inline map[string]string) (string, string) {
		risk, why := "low", ""
		for _, n := range attached {
			r := awsManagedPolicyRisk(n)
			if r == "none" {
				r = local[n]
			}
			if sevRank(r) > sevRank(risk) {
				risk, why = r, n
			}
		}
		for n, doc := range inline {
			dd, err := url.QueryUnescape(doc)
			if err != nil {
				dd = doc
			}
			if awsPolicyAllowsAll(dd) && sevRank("critical") > sevRank(risk) {
				risk, why = "critical", "inline:"+n
			}
		}
		return risk, why
	}
	for _, r := range d.Roles {
		var att []string
		for _, a := range r.Attached {
			att = append(att, a.N)
		}
		in := map[string]string{}
		for _, i := range r.Inline {
			in[i.N] = i.D
		}
		risk, why := judge(att, in)
		roles = append(roles, awsBlastRole{Name: r.Name, ARN: r.ARN, Risk: risk, Why: why, Profiles: r.Profiles})
	}
	for _, u := range d.Users {
		var att []string
		for _, a := range u.Attached {
			att = append(att, a.N)
		}
		in := map[string]string{}
		for _, i := range u.Inline {
			in[i.N] = i.D
		}
		risk, why := judge(att, in)
		users = append(users, awsBlastRole{Name: u.Name, ARN: u.ARN, Risk: risk, Why: why})
	}
	return
}

func awsBlastInstances(b []byte, region string) []awsBlastInstance {
	var r struct {
		Items []struct {
			ID      string   `xml:"instanceId"`
			State   string   `xml:"instanceState>name"`
			IP      string   `xml:"ipAddress"`
			Profile string   `xml:"iamInstanceProfile>arn"`
			SGs     []string `xml:"groupSet>item>groupId"`
			Tags    []struct {
				K string `xml:"key"`
				V string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"reservationSet>item>instancesSet>item"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []awsBlastInstance
	for _, i := range r.Items {
		if i.State == "terminated" {
			continue
		}
		in := awsBlastInstance{ID: i.ID, Region: region, PublicIP: i.IP, ProfileARN: i.Profile, SGs: i.SGs}
		for _, t := range i.Tags {
			if t.K == "Name" {
				in.Name = t.V
			}
		}
		out = append(out, in)
	}
	return out
}

func awsBlastSGs(b []byte, region string) []awsBlastSG {
	var r struct {
		Items []struct {
			ID    string `xml:"groupId"`
			Perms []struct {
				Proto string   `xml:"ipProtocol"`
				From  int      `xml:"fromPort"`
				To    int      `xml:"toPort"`
				V4    []string `xml:"ipRanges>item>cidrIp"`
				V6    []string `xml:"ipv6Ranges>item>cidrIpv6"`
			} `xml:"ipPermissions>item"`
		} `xml:"securityGroupInfo>item"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []awsBlastSG
	for _, g := range r.Items {
		sg := awsBlastSG{ID: g.ID, Region: region}
		var ports []string
		for _, p := range g.Perms {
			world := false
			for _, c := range p.V4 {
				world = world || c == "0.0.0.0/0"
			}
			for _, c := range p.V6 {
				world = world || c == "::/0"
			}
			if !world {
				continue
			}
			sg.OpenWorld = true
			if p.Proto == "-1" {
				sg.OpenSensitive = true
				ports = append(ports, "all")
				continue
			}
			ports = append(ports, fmt.Sprintf("%d-%d", p.From, p.To))
			for port := range awsSensitivePorts {
				if port >= p.From && port <= p.To {
					sg.OpenSensitive = true
				}
			}
		}
		sg.OpenPortsLabel = strings.Join(ports, ",")
		out = append(out, sg)
	}
	return out
}

func awsBlastLambdas(b []byte, region string) []awsBlastLambda {
	var r struct {
		Functions []struct {
			Name string `json:"FunctionName"`
			Role string `json:"Role"`
		} `json:"Functions"`
	}
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []awsBlastLambda
	for _, f := range r.Functions {
		out = append(out, awsBlastLambda{Name: f.Name, Region: region, RoleARN: f.Role})
	}
	return out
}

func awsBlastDBs(b []byte, region string) []awsBlastDB {
	var r struct {
		Items []struct {
			ID     string   `xml:"DBInstanceIdentifier"`
			Engine string   `xml:"Engine"`
			Public bool     `xml:"PubliclyAccessible"`
			SGs    []string `xml:"VpcSecurityGroups>VpcSecurityGroupMembership>VpcSecurityGroupId"`
		} `xml:"DescribeDBInstancesResult>DBInstances>DBInstance"`
	}
	if xml.Unmarshal(b, &r) != nil {
		return nil
	}
	var out []awsBlastDB
	for _, d := range r.Items {
		out = append(out, awsBlastDB{ID: d.ID, Region: region, Engine: d.Engine, Public: d.Public, SGs: d.SGs})
	}
	return out
}

// buildAWSBlast assembles the graph and the high-risk paths. Pure function.
func buildAWSBlast(in awsBlastInput, connID int64, accountID string) *BlastRadiusResult {
	res := &BlastRadiusResult{ConnectorID: connID, ProjectID: accountID, ScannedAt: time.Now()}
	nodes := map[string]*BlastNode{}
	var edges []BlastEdge
	byRes := map[string][]CSPMFinding{}
	if in.CSPM != nil {
		for _, f := range in.CSPM.Findings {
			byRes[f.Resource] = append(byRes[f.Resource], f)
		}
	}
	add := func(id, name, full, typ string, props map[string]string) *BlastNode {
		if n, ok := nodes[id]; ok {
			return n
		}
		n := &BlastNode{ID: id, Name: name, FullName: full, Type: typ, Risk: "none", Properties: props}
		for _, key := range []string{name, id} {
			if fs := byRes[key]; len(fs) > 0 {
				n.HasFindings, n.FindingCount = true, len(fs)
				for _, f := range fs {
					n.Risk = maxSev(n.Risk, f.Severity)
				}
				break
			}
		}
		nodes[id] = n
		return n
	}
	edge := func(from, to, rel string, boost bool) {
		edges = append(edges, BlastEdge{From: from, To: to, Relationship: rel, RiskBoost: boost})
	}

	roleByProfile := map[string]awsBlastRole{}
	for _, r := range in.Roles {
		for _, p := range r.Profiles {
			roleByProfile[p] = r
		}
	}
	roleByARN := map[string]awsBlastRole{}
	for _, r := range in.Roles {
		roleByARN[r.ARN] = r
	}
	sgs := map[string]awsBlastSG{}
	for _, g := range in.SGs {
		sgs[g.Region+"|"+g.ID] = g
	}

	var paths []BlastPath
	for _, inst := range in.Instances {
		iid := "ec2:" + inst.Region + "|" + inst.ID
		label := inst.Name
		if label == "" {
			label = inst.ID
		}
		n := add(iid, label, inst.ID, "vm", map[string]string{"region": inst.Region, "public_ip": inst.PublicIP})
		exposed, sensitive, ports := false, false, ""
		for _, sg := range inst.SGs {
			g, ok := sgs[inst.Region+"|"+sg]
			sid := "sg:" + inst.Region + "|" + sg
			add(sid, sg, sg, "firewall", map[string]string{"open_ports": g.OpenPortsLabel})
			edge(iid, sid, "protected_by", false)
			if ok && g.OpenWorld && inst.PublicIP != "" {
				exposed = true
				sensitive = sensitive || g.OpenSensitive
				ports = g.OpenPortsLabel
				nodes[sid].Risk = maxSev(nodes[sid].Risk, map[bool]string{true: "high", false: "medium"}[g.OpenSensitive])
				edge("internet:public", sid, "can_reach", true)
				edge(sid, iid, "allows", true)
			}
		}
		if exposed {
			add("internet:public", "Internet", "Internet", "internet", nil)
			n.Risk = maxSev(n.Risk, map[bool]string{true: "high", false: "medium"}[sensitive])
			res.Summary.PublicExposures++
		}
		if r, ok := roleByProfile[inst.ProfileARN]; ok && inst.ProfileARN != "" {
			rid := "role:" + r.Name
			rn := add(rid, r.Name, r.ARN, "iam_role", map[string]string{"why": r.Why})
			rn.Risk = maxSev(rn.Risk, r.Risk)
			edge(iid, rid, "uses_role", sevRank(r.Risk) >= 3)
			if sevRank(r.Risk) >= 3 {
				res.Summary.PrivEscPaths++
			}
			if exposed && sevRank(r.Risk) >= 3 {
				sev := "high"
				if r.Risk == "critical" && sensitive {
					sev = "critical"
				}
				paths = append(paths, BlastPath{StartNode: "internet:public",
					Path: []string{"internet:public", iid, rid}, EndPrivilege: "aws_" + r.Risk + "_role", Severity: sev,
					Description: fmt.Sprintf("Instance %s is reachable from the internet (ports %s) and runs as role %s (%s) — compromise yields that role's AWS access", label, ports, r.Name, r.Why)})
			}
		}
	}
	for _, l := range in.Lambdas {
		lid := "lambda:" + l.Region + "|" + l.Name
		add(lid, l.Name, l.Name, "function", map[string]string{"region": l.Region})
		if r, ok := roleByARN[l.RoleARN]; ok {
			rid := "role:" + r.Name
			rn := add(rid, r.Name, r.ARN, "iam_role", map[string]string{"why": r.Why})
			rn.Risk = maxSev(rn.Risk, r.Risk)
			edge(lid, rid, "uses_role", sevRank(r.Risk) >= 3)
			if sevRank(r.Risk) >= 3 {
				res.Summary.PrivEscPaths++
			}
		}
	}
	for _, d := range in.DBs {
		did := "rds:" + d.Region + "|" + d.ID
		n := add(did, d.ID, d.ID, "database", map[string]string{"region": d.Region, "engine": d.Engine})
		exposed, ports := false, ""
		for _, sg := range d.SGs {
			g, ok := sgs[d.Region+"|"+sg]
			sid := "sg:" + d.Region + "|" + sg
			add(sid, sg, sg, "firewall", map[string]string{"open_ports": g.OpenPortsLabel})
			edge(did, sid, "protected_by", false)
			if ok && g.OpenWorld && d.Public {
				exposed, ports = true, g.OpenPortsLabel
				nodes[sid].Risk = maxSev(nodes[sid].Risk, "high")
				edge("internet:public", sid, "can_reach", true)
				edge(sid, did, "allows", true)
			}
		}
		if exposed {
			add("internet:public", "Internet", "Internet", "internet", nil)
			n.Risk = maxSev(n.Risk, "high")
			res.Summary.PublicExposures++
			paths = append(paths, BlastPath{StartNode: "internet:public", Path: []string{"internet:public", did},
				EndPrivilege: "database_access", Severity: "high",
				Description: fmt.Sprintf("Database %s (%s) is publicly accessible and its security group is open to the internet (ports %s)", d.ID, d.Engine, ports)})
		}
	}
	for _, u := range in.Users {
		if sevRank(u.Risk) >= 3 {
			uid := "user:" + u.Name
			n := add(uid, u.Name, u.ARN, "user", map[string]string{"why": u.Why})
			n.Risk = maxSev(n.Risk, u.Risk)
			res.Summary.PrivEscPaths++
		}
	}
	if in.CSPM != nil {
		for _, f := range in.CSPM.Findings {
			if f.ResourceType != "s3_bucket" {
				continue
			}
			bid := "bucket:" + f.Resource
			b := add(bid, f.Resource, f.Resource, "storage_bucket", nil)
			b.Risk = maxSev(b.Risk, f.Severity)
			if strings.Contains(strings.ToLower(f.Title), "public") {
				add("internet:public", "Internet", "Internet", "internet", nil)
				edge("internet:public", bid, "can_reach", true)
				res.Summary.PublicExposures++
				if f.Severity == "critical" || f.Severity == "high" {
					paths = append(paths, BlastPath{StartNode: "internet:public", Path: []string{"internet:public", bid},
						EndPrivilege: "public_data_exposure", Severity: f.Severity,
						Description: fmt.Sprintf("Bucket %s is publicly accessible: %s", f.Resource, f.Title)})
				}
			}
		}
	}

	list := make([]BlastNode, 0, len(nodes))
	high := 0
	for _, n := range nodes {
		list = append(list, *n)
		if sevRank(n.Risk) >= 3 {
			high++
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	sort.SliceStable(paths, func(i, j int) bool { return sevRank(paths[i].Severity) > sevRank(paths[j].Severity) })
	if len(paths) > 20 {
		paths = paths[:20]
	}
	res.Nodes, res.Edges, res.HighRiskPaths = list, edges, paths
	res.Summary.TotalNodes, res.Summary.TotalEdges = len(list), len(edges)
	res.Summary.HighRiskNodes, res.Summary.CriticalPaths = high, len(paths)
	return res
}

// RunAWSBlastRadius collects IAM, instance and security-group data and builds the graph.
func RunAWSBlastRadius(ctx context.Context, creds awsCreds, accountID string, cspm *CSPMResult, connID int64) (*BlastRadiusResult, error) {
	in := awsBlastInput{CSPM: cspm}
	var errs []string
	marker := ""
	got := false
	for page := 0; page < 10; page++ {
		form := "Action=GetAccountAuthorizationDetails&Version=2010-05-08&Filter.member.1=Role&Filter.member.2=User&Filter.member.3=LocalManagedPolicy&MaxItems=100"
		if marker != "" {
			form += "&Marker=" + url.QueryEscape(marker)
		}
		b, c, err := awsQueryCall(ctx, creds, "iam", "iam.amazonaws.com", form)
		if err != nil || c != 200 {
			errs = append(errs, "iam: GetAccountAuthorizationDetails denied or failed")
			break
		}
		got = true
		r, u, _ := awsBlastEntities(b)
		in.Roles = append(in.Roles, r...)
		in.Users = append(in.Users, u...)
		var t struct {
			Trunc  bool   `xml:"GetAccountAuthorizationDetailsResult>IsTruncated"`
			Marker string `xml:"GetAccountAuthorizationDetailsResult>Marker"`
		}
		if xml.Unmarshal(b, &t) != nil || !t.Trunc || t.Marker == "" {
			break
		}
		marker = t.Marker
	}
	if !got {
		return nil, fmt.Errorf("cannot read IAM (need iam:GetAccountAuthorizationDetails / SecurityAudit)")
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
	var mu sync.Mutex
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
			host := "ec2." + region + ".amazonaws.com"
			ib, ic, ierr := awsQueryCall(ctx, rc, "ec2", host, "Action=DescribeInstances&Version=2016-11-15&MaxResults=1000")
			sb, sc, serr := awsQueryCall(ctx, rc, "ec2", host, "Action=DescribeSecurityGroups&Version=2016-11-15")
			lb, lc, lerr := awsRESTGet(ctx, rc, "lambda", "lambda."+region+".amazonaws.com", "/2015-03-31/functions/?MaxItems=50")
			db, dc, derr := awsQueryCall(ctx, rc, "rds", "rds."+region+".amazonaws.com", "Action=DescribeDBInstances&Version=2014-10-31")
			mu.Lock()
			defer mu.Unlock()
			if lerr != nil || lc != 200 {
				errs = append(errs, region+": Lambda ListFunctions failed")
			} else {
				in.Lambdas = append(in.Lambdas, awsBlastLambdas(lb, region)...)
			}
			if derr != nil || dc != 200 {
				errs = append(errs, region+": RDS DescribeDBInstances failed")
			} else {
				in.DBs = append(in.DBs, awsBlastDBs(db, region)...)
			}
			if ierr != nil || ic != 200 {
				errs = append(errs, region+": DescribeInstances failed")
			} else {
				in.Instances = append(in.Instances, awsBlastInstances(ib, region)...)
			}
			if serr != nil || sc != 200 {
				errs = append(errs, region+": DescribeSecurityGroups failed")
			} else {
				in.SGs = append(in.SGs, awsBlastSGs(sb, region)...)
			}
		}(region)
	}
	wg.Wait()
	res := buildAWSBlast(in, connID, accountID)
	sort.Strings(errs)
	res.Errors = errs
	return res, nil
}

func handleRunAWSBlast(db *store.DB, id int64, conn *store.CloudConnector, w http.ResponseWriter, r *http.Request) {
	creds, err := resolveAWSCreds(r.Context(), conn.Credentials)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()
	var cspm *CSPMResult
	if val, e := db.GetSetting(r.Context(), fmt.Sprintf("cspm:aws:%d", id)); e == nil && val != "" {
		cspm = &CSPMResult{}
		_ = json.Unmarshal([]byte(val), cspm)
	}
	res, err := RunAWSBlastRadius(ctx, creds, conn.AccountID, cspm, id)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	data, _ := json.Marshal(res)
	_ = db.SetSetting(r.Context(), fmt.Sprintf("blast:aws:%d", id), string(data))
	writeJSON(w, 200, res)
}
