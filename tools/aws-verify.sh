#!/usr/bin/env bash
# aws-verify.sh - provision an AWS test account for ObsidianWatch, generate activity, check the results, clean up.
#
# Run it in AWS CloudShell (console → the >_ icon), signed in as an administrator of a TEST account:
#
#   bash aws-verify.sh up         create the connector identity, a CloudTrail trail and deliberately weak (but
#                                 unexposed) settings that the posture scan must flag; prints the connector values
#   bash aws-verify.sh attack     generate the CloudTrail activity the detections must alert on (run after "up";
#                                 again whenever you like - each run makes new events)
#   bash aws-verify.sh check      ask ObsidianWatch what it saw and print PASS / NOT YET per expectation
#                                 (needs OW_URL and a login, see below; without them it prints the checklist)
#   bash aws-verify.sh status     what this script created
#   bash aws-verify.sh down       delete everything it created and restore the password policy
#
# Options for "up" (each costs a little, so they are off by default):
#   --guardduty   enable GuardDuty (30-day free trial) and create sample findings: tests GuardDuty ingestion and rules
#   --ebs         a 1 GB empty volume and a PUBLIC snapshot of it: tests the public-snapshot check and rule (cents)
#   --kms         a KMS key without rotation ($1/month, prorated; "down" schedules its deletion, which is free)
#   --no-trail    do not create a CloudTrail trail (LookupEvents works without one; the "no multi-region trail"
#                 finding then stays open)
#
# Connect ObsidianWatch automatically (optional; otherwise paste the printed values into Cloud → Add connector):
#   export OW_URL=https://siem.example.com     the console address reachable from CloudShell
#   export OW_USER=admin OW_PASS='…'           or OW_TOKEN=<JWT from the browser's localStorage "token">
#   export OW_INSECURE=1                       if the console uses a self-signed certificate
#
# Everything is named ow-verify-* and tagged owner=obsidianwatch-verify. Nothing is exposed: the open security
# groups are attached to nothing, the weak bucket is empty, the user with a console password has no permissions,
# the role that anyone can assume has an explicit deny-all policy, the public snapshot (--ebs) is of an empty volume.
# Use a test account anyway: "up" weakens the account password policy until "down" restores it.
set -uo pipefail

P=ow-verify
TAG_KEY=owner TAG_VAL=obsidianwatch-verify
STATE_DIR="${OW_VERIFY_DIR:-$HOME/.ow-aws-verify}"
STATE="$STATE_DIR/state"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}"
REGION="${REGION:-us-east-1}"
export AWS_REGION="$REGION" AWS_PAGER=""

say()  { printf '\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
rnd()  { python3 -c "import secrets,sys;print(secrets.token_hex(int(sys.argv[1])))" "${1:-8}"; }
pw()   { python3 -c "import secrets,string;a=string.ascii_letters+string.digits;print('Ow!'+''.join(secrets.choice(a) for _ in range(24))+'9a')"; }
jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$1"; }

mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; touch "$STATE"; chmod 600 "$STATE"
st_get() { sed -n "s/^$1=//p" "$STATE" | tail -1; }
st_set() { grep -v "^$1=" "$STATE" > "$STATE.tmp" 2>/dev/null || true; echo "$1=$2" >> "$STATE.tmp"; mv "$STATE.tmp" "$STATE"; chmod 600 "$STATE"; }

command -v aws >/dev/null || die "the AWS CLI is not installed (use AWS CloudShell)"
command -v python3 >/dev/null || die "python3 is needed"

whoami_aws() {
  ACCT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || die "no AWS credentials (run in CloudShell, or configure the CLI)"
  CALLER=$(aws sts get-caller-identity --query Arn --output text)
}

tags_iam() { echo "Key=$TAG_KEY,Value=$TAG_VAL"; }
tagspec() { echo "ResourceType=$1,Tags=[{Key=Name,Value=$2},{Key=$TAG_KEY,Value=$TAG_VAL}]"; }

# ── ObsidianWatch API (optional) ─────────────────────────────────────────────────
ow_enabled() { [ -n "${OW_URL:-}" ] && { [ -n "${OW_TOKEN:-}" ] || [ -n "${OW_USER:-}" ]; }; }
ow_curl() { local k=""; [ -n "${OW_INSECURE:-}" ] && k="-k"; curl -s $k --max-time 60 "$@"; }
ow_login() {
  [ -n "${OW_TOKEN:-}" ] && return 0
  local body; body=$(python3 -c "import json,os;print(json.dumps({'username':os.environ['OW_USER'],'password':os.environ.get('OW_PASS','')}))")
  OW_TOKEN=$(ow_curl -X POST -H 'Content-Type: application/json' -d "$body" "${OW_URL%/}/auth/login" | jget "d.get('token','')" 2>/dev/null || true)
  [ -n "$OW_TOKEN" ] || die "ObsidianWatch login failed at $OW_URL (check OW_USER/OW_PASS; an account with MFA needs OW_TOKEN)"
}
ow() { local m=$1 path=$2; shift 2; ow_curl -X "$m" -H "Authorization: Bearer $OW_TOKEN" -H 'Content-Type: application/json' "$@" "${OW_URL%/}$path"; }
ow_connector_id() {
  ow GET /api/v1/cloud-connectors | python3 -c "
import json,sys
d=json.load(sys.stdin)
for c in d.get('connectors') or []:
    if c.get('provider')=='aws' and c.get('account_id')=='$ACCT': print(c['id']); break" 2>/dev/null
}

# ── up ───────────────────────────────────────────────────────────────────────────
up() {
  local GD="" EBS="" KMS="" TRAIL=1
  for a in "$@"; do case $a in --guardduty) GD=1 ;; --ebs) EBS=1 ;; --kms) KMS=1 ;; --no-trail) TRAIL="" ;; *) die "unknown option $a" ;; esac; done
  whoami_aws
  say "account $ACCT, region $REGION, as $CALLER"
  case "$CALLER" in *:root) warn "you are signed in as root: fine for this test, but expect the root-activity alert (C-AWS-042)";; esac
  st_set ACCT "$ACCT"; st_set REGION "$REGION"

  # 1. Connector identity: a user that may only assume a read-only role (the recommended model).
  say "connector identity (user $P-connector → role $P-readonly with an external ID)"
  local ext; ext=$(st_get EXTERNAL_ID); [ -n "$ext" ] || { ext=$(rnd 16); st_set EXTERNAL_ID "$ext"; }
  aws iam get-user --user-name $P-connector >/dev/null 2>&1 || aws iam create-user --user-name $P-connector --tags "$(tags_iam)" >/dev/null || die "create-user failed"
  local role_arn="arn:aws:iam::$ACCT:role/$P-readonly"
  cat > "$STATE_DIR/trust.json" <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::$ACCT:user/$P-connector"},
 "Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"$ext"}}}]}
EOF
  for i in 1 2 3 4 5 6; do   # a new user takes a few seconds to be usable as a principal
    if aws iam get-role --role-name $P-readonly >/dev/null 2>&1; then
      aws iam update-assume-role-policy --role-name $P-readonly --policy-document "file://$STATE_DIR/trust.json" >/dev/null 2>&1 && break
    else
      aws iam create-role --role-name $P-readonly --assume-role-policy-document "file://$STATE_DIR/trust.json" \
        --description "ObsidianWatch read-only (aws-verify.sh)" --tags "$(tags_iam)" >/dev/null 2>&1 && break
    fi
    sleep 5
  done
  aws iam get-role --role-name $P-readonly >/dev/null 2>&1 || die "could not create role $P-readonly"
  aws iam attach-role-policy --role-name $P-readonly --policy-arn arn:aws:iam::aws:policy/SecurityAudit
  local trail_bucket="$P-trail-$ACCT-$REGION"
  cat > "$STATE_DIR/extra.json" <<EOF
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["cloudtrail:LookupEvents","guardduty:ListDetectors","guardduty:ListFindings","guardduty:GetFindings",
   "securityhub:GetFindings","securityhub:DescribeHub","s3:GetBucketLocation","s3:GetAccountPublicAccessBlock"],"Resource":"*"},
 {"Effect":"Allow","Action":["s3:ListBucket","s3:GetObject"],"Resource":["arn:aws:s3:::$trail_bucket","arn:aws:s3:::$trail_bucket/*"]}]}
EOF
  aws iam put-role-policy --role-name $P-readonly --policy-name ow-extra-reads --policy-document "file://$STATE_DIR/extra.json"
  aws iam put-user-policy --user-name $P-connector --policy-name assume-readonly \
    --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Resource\":\"$role_arn\"}]}"
  if [ -z "$(st_get CONNECTOR_KEY_ID)" ]; then
    local k; k=$(aws iam create-access-key --user-name $P-connector --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text) || die "create-access-key failed"
    st_set CONNECTOR_KEY_ID "$(echo "$k" | cut -f1)"; st_set CONNECTOR_SECRET "$(echo "$k" | cut -f2)"
  fi
  ok "role $role_arn (SecurityAudit + LookupEvents/GuardDuty/Security Hub reads)"
  printf '   waiting until the new key can assume the role'
  local assumed=""
  for i in $(seq 1 24); do
    if AWS_ACCESS_KEY_ID=$(st_get CONNECTOR_KEY_ID) AWS_SECRET_ACCESS_KEY=$(st_get CONNECTOR_SECRET) AWS_SESSION_TOKEN= \
       aws sts assume-role --role-arn "$role_arn" --role-session-name ow-verify-check --external-id "$ext" >/dev/null 2>&1; then assumed=1; break; fi
    printf '.'; sleep 5
  done
  echo; [ -n "$assumed" ] && ok "the connector key assumes the role" || warn "the key could not assume the role yet (IAM can take a minute); ObsidianWatch's Test Connection will tell"

  # 2. CloudTrail: one multi-region trail with log file validation (the first copy of management events is free).
  if [ -n "$TRAIL" ]; then
    say "CloudTrail trail $P-trail → s3://$trail_bucket"
    local existing; existing=$(aws cloudtrail describe-trails --query "trailList[?IsMultiRegionTrail && Name!='$P-trail'].Name" --output text 2>/dev/null)
    if [ -n "$existing" ] && [ "$existing" != "None" ]; then
      ok "a multi-region trail already exists ($existing): not creating another (a second copy of events is billed)"
    else
      mkbucket "$trail_bucket"
      cat > "$STATE_DIR/trailpolicy.json" <<EOF
{"Version":"2012-10-17","Statement":[
 {"Sid":"AclCheck","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::$trail_bucket",
  "Condition":{"StringEquals":{"aws:SourceArn":"arn:aws:cloudtrail:$REGION:$ACCT:trail/$P-trail"}}},
 {"Sid":"Write","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::$trail_bucket/AWSLogs/$ACCT/*",
  "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control","aws:SourceArn":"arn:aws:cloudtrail:$REGION:$ACCT:trail/$P-trail"}}},
 {"Sid":"TLSOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::$trail_bucket","arn:aws:s3:::$trail_bucket/*"],
  "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}
EOF
      aws s3api put-bucket-policy --bucket "$trail_bucket" --policy "file://$STATE_DIR/trailpolicy.json"
      aws cloudtrail get-trail --name $P-trail >/dev/null 2>&1 || aws cloudtrail create-trail --name $P-trail --s3-bucket-name "$trail_bucket" \
        --is-multi-region-trail --enable-log-file-validation --tags-list "Key=$TAG_KEY,Value=$TAG_VAL" >/dev/null || warn "create-trail failed"
      aws cloudtrail start-logging --name $P-trail 2>/dev/null && { st_set TRAIL 1; ok "trail logging (multi-region, log file validation on)"; }
    fi
  fi

  # 3. Weak settings the posture scan must flag. Nothing here is reachable or holds data.
  say "deliberately weak, unexposed resources"
  local vpc; vpc=$(st_get VPC_ID)
  if [ -z "$vpc" ]; then
    vpc=$(aws ec2 create-vpc --cidr-block 10.99.0.0/16 --tag-specifications "$(tagspec vpc $P-vpc)" --query Vpc.VpcId --output text) || die "create-vpc failed"
    st_set VPC_ID "$vpc"
  fi
  ok "VPC $vpc without flow logs                  → 'VPC … has no flow logs' (medium)"
  sg() {  # name, ip-permissions
    local id; id=$(st_get "SG_$1")
    if [ -z "$id" ]; then
      id=$(aws ec2 create-security-group --group-name "$P-$1" --description "ObsidianWatch verify: $1 (attached to nothing)" --vpc-id "$vpc" \
        --tag-specifications "$(tagspec security-group $P-$1)" --query GroupId --output text) || return 1
      st_set "SG_$1" "$id"
      aws ec2 authorize-security-group-ingress --group-id "$id" --ip-permissions "$2" >/dev/null
    fi
    echo "$id"
  }
  ok "SG $(sg open-ssh 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0}]') opens 22 to 0.0.0.0/0   → 'exposes port 22' (high), alert C-NET-001"
  ok "SG $(sg open-all 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]') allows all traffic         → 'allows all traffic from the internet' (critical), alert C-NET-002"

  local weak="$P-weak-$ACCT-$REGION"
  mkbucket "$weak"
  aws s3api delete-public-access-block --bucket "$weak" 2>/dev/null
  st_set WEAK_BUCKET "$weak"
  local apab; apab=$(aws s3control get-public-access-block --account-id "$ACCT" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text 2>/dev/null || echo none)
  if [ "$(echo "$apab" | tr -s '\t ' '\n' | grep -c True)" = 4 ]; then
    ok "bucket $weak: no bucket-level Block Public Access, but account-level BPA is on → no BPA finding (correct)"
    st_set ACCOUNT_PAB on
  else
    ok "bucket $weak: no Block Public Access         → 'has no Block Public Access configuration' (medium)"
    st_set ACCOUNT_PAB off
  fi
  ok "bucket $weak: no versioning, logging or TLS-only policy → three low findings"

  if ! aws iam get-user --user-name $P-nomfa >/dev/null 2>&1; then
    aws iam create-user --user-name $P-nomfa --tags "$(tags_iam)" >/dev/null
    local p; p=$(pw)
    aws iam create-login-profile --user-name $P-nomfa --password "$p" --no-password-reset-required >/dev/null 2>&1 \
      && { st_set NOMFA_PASSWORD "$p"; } || warn "create-login-profile failed (the password policy may need a longer password)"
  fi
  ok "user $P-nomfa: console password, no MFA, no permissions → 'has a console password but no MFA' (high), alerts C-AWS-016, C-AWS-044"

  aws iam get-policy --policy-arn "arn:aws:iam::$ACCT:policy/$P-star" >/dev/null 2>&1 || aws iam create-policy --policy-name $P-star \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' --tags "$(tags_iam)" >/dev/null
  ok "policy $P-star (*:*, attached to nothing)      → 'allows all actions on all resources' (medium)"

  if ! aws iam get-role --role-name $P-open-trust >/dev/null 2>&1; then
    aws iam create-role --role-name $P-open-trust --tags "$(tags_iam)" --description "ObsidianWatch verify: open trust, deny-all permissions" \
      --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}' >/dev/null \
      || warn "create-role with an open trust failed"
    aws iam put-role-policy --role-name $P-open-trust --policy-name deny-all \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}' 2>/dev/null
  fi
  ok "role $P-open-trust (any principal, deny-all)  → 'can be assumed by any AWS principal' (critical)"

  if [ -z "$(st_get PWPOLICY_SAVED)" ]; then
    aws iam get-account-password-policy --query PasswordPolicy --output json > "$STATE_DIR/pwpolicy.json" 2>/dev/null || echo none > "$STATE_DIR/pwpolicy.json"
    st_set PWPOLICY_SAVED 1
  fi
  aws iam update-account-password-policy --minimum-password-length 8 --no-require-symbols --no-require-numbers \
    --no-require-uppercase-characters --no-require-lowercase-characters --allow-users-to-change-password
  ok "password policy: length 8, no reuse or expiry → three low findings, alert C-AWS-018 (\"down\" restores yours)"

  if [ -n "$EBS" ]; then
    local az; az=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)
    local vol; vol=$(st_get VOLUME_ID)
    [ -n "$vol" ] || { vol=$(aws ec2 create-volume --availability-zone "$az" --size 1 --volume-type gp3 --tag-specifications "$(tagspec volume $P-empty)" --query VolumeId --output text) && st_set VOLUME_ID "$vol"; }
    aws ec2 wait volume-available --volume-ids "$vol"
    local snap; snap=$(st_get SNAPSHOT_ID)
    [ -n "$snap" ] || { snap=$(aws ec2 create-snapshot --volume-id "$vol" --description "ObsidianWatch verify (empty)" --tag-specifications "$(tagspec snapshot $P-public)" --query SnapshotId --output text) && st_set SNAPSHOT_ID "$snap"; }
    aws ec2 wait snapshot-completed --snapshot-ids "$snap"
    aws ec2 modify-snapshot-attribute --snapshot-id "$snap" --attribute createVolumePermission --operation-type add --group-names all \
      && ok "snapshot $snap of an empty volume is PUBLIC → 'EBS snapshot … is public' (critical), alert C-AWS-022" \
      || warn "making the snapshot public failed (account-level 'block public access for snapshots' may be on: that is good)"
  fi
  if [ -n "$KMS" ]; then
    local key; key=$(st_get KMS_KEY)
    [ -n "$key" ] || { key=$(aws kms create-key --description "ObsidianWatch verify (no rotation)" --tags "TagKey=$TAG_KEY,TagValue=$TAG_VAL" --query KeyMetadata.KeyId --output text) && st_set KMS_KEY "$key"; }
    ok "KMS key $key without rotation → 'has rotation disabled' (low); \"down\" schedules deletion → alert C-XCLOUD-005"
  fi
  if [ -n "$GD" ]; then
    local det; det=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null)
    if [ -z "$det" ] || [ "$det" = None ]; then
      det=$(aws guardduty create-detector --enable --tags "$TAG_KEY=$TAG_VAL" --query DetectorId --output text 2>/dev/null) && st_set GD_CREATED "$det" \
        || warn "GuardDuty could not be enabled (it may not be available on this account's plan)"
    fi
    if [ -n "$det" ] && [ "$det" != None ]; then
      st_set GD_DETECTOR "$det"
      aws guardduty create-sample-findings --detector-id "$det" --finding-types \
        Recon:EC2/PortProbeUnprotectedPort Backdoor:EC2/C\&CActivity.B CryptoCurrency:EC2/BitcoinTool.B >/dev/null 2>&1 \
        && ok "GuardDuty $det with 3 sample findings → cloud.guardduty events, alerts C-AWS-029/030/032" || warn "sample findings failed"
    fi
  fi

  # 4. Connector values.
  local out="$STATE_DIR/connector.txt"
  cat > "$out" <<EOF
ObsidianWatch → Cloud → Add connector → Amazon Web Services
  Access Key ID        $(st_get CONNECTOR_KEY_ID)
  Secret Access Key    $(st_get CONNECTOR_SECRET)
  Region               $REGION
  Role ARN to assume   $role_arn
  External ID          $ext
  Account ID           $ACCT
EOF
  chmod 600 "$out"
  say "connector values (also in $out)"; sed 's/^/   /' "$out" | tail -6

  if ow_enabled; then
    ow_login
    say "creating the connector in ObsidianWatch ($OW_URL)"
    local body; body=$(python3 -c "
import json;print(json.dumps({'provider':'aws','credentials':{'access_key_id':'$(st_get CONNECTOR_KEY_ID)','secret_access_key':'$(st_get CONNECTOR_SECRET)',
 'region':'$REGION','role_arn':'$role_arn','external_id':'$ext','account_id':'$ACCT'}}))")
    local t; t=$(ow POST /api/v1/cloud-connectors/test -d "$body")
    echo "$t" | grep -q '"ok"' && ok "Test Connection: $t" || warn "Test Connection: $t"
    local id; id=$(ow POST /api/v1/cloud-connectors -d "$body" | jget "d.get('id','')" 2>/dev/null)
    [ -n "$id" ] || die "saving the connector failed"
    st_set OW_CONNECTOR "$id"
    ow POST "/api/v1/cloud-connectors/$id/sync" >/dev/null; ok "connector $id saved, first sync started"
    ow POST "/api/v1/cloud-connectors/$id/cspm" >/dev/null; ok "posture scan started"
  else
    say "next: add the connector in ObsidianWatch with the values above (or set OW_URL + OW_USER/OW_PASS and run up again)"
  fi
  echo
  echo "Then: bash $0 attack    (and about 15 minutes later)    bash $0 check"
}

mkbucket() {
  aws s3api head-bucket --bucket "$1" >/dev/null 2>&1 && return 0
  if [ "$REGION" = us-east-1 ]; then aws s3api create-bucket --bucket "$1" >/dev/null
  else aws s3api create-bucket --bucket "$1" --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null; fi || die "create-bucket $1 failed"
  aws s3api put-bucket-tagging --bucket "$1" --tagging "TagSet=[{Key=$TAG_KEY,Value=$TAG_VAL}]"
}

# ── attack ───────────────────────────────────────────────────────────────────────
attack() {
  whoami_aws
  [ -n "$(st_get VPC_ID)" ] || die "run 'up' first"
  local ts; ts=$(date +%H%M%S)
  say "generating CloudTrail activity in $ACCT ($REGION); every name is $P-*"

  # Logging tampered with, then a new identity given admin rights (sequence rules).
  if [ -n "$(st_get TRAIL)" ]; then
    aws cloudtrail stop-logging --name $P-trail && ok "StopLogging on $P-trail           → C-XCLOUD-003 'Cloud Logging Disabled'"
  fi
  local tmp=$P-temp-$ts
  aws iam create-user --user-name "$tmp" --tags "$(tags_iam)" >/dev/null && ok "CreateUser $tmp                    → C-AWS-016, CORR-SEQ-AWS-003 (after StopLogging)"
  aws iam attach-user-policy --user-name "$tmp" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
    && ok "AttachUserPolicy AdministratorAccess → C-AWS-045, CORR-SEQ-AWS-002 (user created, then granted)"
  aws iam detach-user-policy --user-name "$tmp" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
  aws iam delete-user --user-name "$tmp"
  [ -n "$(st_get TRAIL)" ] && aws cloudtrail start-logging --name $P-trail && ok "StartLogging (trail back on), temp user deleted"

  aws iam update-login-profile --user-name $P-nomfa --password "$(pw)" --no-password-reset-required 2>/dev/null \
    && ok "UpdateLoginProfile $P-nomfa               → C-AWS-044"
  aws iam update-account-password-policy --minimum-password-length 8 --allow-users-to-change-password \
    && ok "UpdateAccountPasswordPolicy (weak)      → C-AWS-018"

  local sg; sg=$(st_get SG_open-ssh)
  aws ec2 authorize-security-group-ingress --group-id "$sg" --protocol tcp --port 3389 --cidr 0.0.0.0/0 >/dev/null 2>&1 \
    && ok "AuthorizeSecurityGroupIngress 3389 from 0.0.0.0/0 → C-NET-001"
  aws ec2 revoke-security-group-ingress --group-id "$sg" --protocol tcp --port 3389 --cidr 0.0.0.0/0 >/dev/null 2>&1

  aws ec2 create-key-pair --key-name "$P-key-$ts" --query KeyPairId --output text >/dev/null \
    && aws ec2 delete-key-pair --key-name "$P-key-$ts" && ok "CreateKeyPair (then deleted)           → C-AWS-025"

  local sec="$P-secret-$ts"
  if aws secretsmanager create-secret --name "$sec" --secret-string "not-a-real-secret" --tags "Key=$TAG_KEY,Value=$TAG_VAL" >/dev/null; then
    aws secretsmanager get-secret-value --secret-id "$sec" >/dev/null && ok "GetSecretValue                         → C-AWS-026"
    aws secretsmanager delete-secret --secret-id "$sec" --force-delete-without-recovery >/dev/null && ok "DeleteSecret (no recovery)            → C-AWS-027"
  fi
  if aws ssm put-parameter --name "/$P/param-$ts" --type SecureString --value "not-a-real-secret" >/dev/null; then
    aws ssm get-parameter --name "/$P/param-$ts" --with-decryption >/dev/null && ok "GetParameter --with-decryption          → C-AWS-028"
    aws ssm delete-parameter --name "/$P/param-$ts"
  fi

  local b; b=$(st_get WEAK_BUCKET)
  aws s3api put-bucket-versioning --bucket "$b" --versioning-configuration Status=Enabled
  aws s3api put-bucket-versioning --bucket "$b" --versioning-configuration Status=Suspended && ok "PutBucketVersioning Suspended         → C-AWS-012"
  aws s3api delete-bucket-encryption --bucket "$b" && ok "DeleteBucketEncryption                 → C-AWS-015"

  # Reconnaissance from CloudShell (a different user agent than ObsidianWatch's own scans, which must stay silent).
  aws s3api list-buckets >/dev/null; aws iam list-users >/dev/null; aws ec2 describe-instances >/dev/null
  aws iam generate-credential-report >/dev/null
  ok "ListBuckets/ListUsers/DescribeInstances/GenerateCredentialReport → C-RECON-001, C-RECON-002"

  echo
  echo "CloudTrail delivers these to LookupEvents in 5-15 minutes and ObsidianWatch syncs every 5 minutes."
  echo "Then: bash $0 check   (or look at Alerts, and the connector's Event Timeline)"
  echo "Manual extra: sign in to the console as $P-nomfa (password in $STATE, sign-in URL https://$ACCT.signin.aws.amazon.com/console) → C-AWS-041"
}

# ── check ────────────────────────────────────────────────────────────────────────
EXPECT_ALERTS=(
  "C-AWS-016|IAM User Created"
  "C-AWS-044|AWS Login Profile Created or Changed"
  "C-AWS-045|AWS AdministratorAccess Policy Attached"
  "C-AWS-018|IAM Password Policy Weakened"
  "C-NET-001|Cloud Security Group Opens SSH/RDP to Internet"
  "C-NET-002|AWS Security Group Opens All Ports to Internet"
  "C-AWS-025|EC2 SSH Key Pair Created"
  "C-AWS-026|Secrets Manager Secret Accessed"
  "C-AWS-027|Secrets Manager Secret Deleted"
  "C-AWS-028|Parameter Store Sensitive Value Accessed"
  "C-AWS-012|S3 Bucket Versioning Disabled"
  "C-AWS-015|S3 Bucket Encryption Removed"
  "C-XCLOUD-003|Cloud Logging Disabled"
  "CORR-SEQ-AWS-002|AWS identity created or given a key, then granted permissions"
  "CORR-SEQ-AWS-003|AWS logging tampered with, then new resources or identities created"
  "C-RECON-001|AWS Cloud Enumeration"
  "C-RECON-002|AWS IAM Credential Report Generated"
)
EXPECT_FINDINGS=(
  "exposes port 22 to the internet"
  "allows all traffic from the internet"
  "has no flow logs"
  "does not have versioning enabled"
  "has no server access logging"
  "policy does not require TLS"
  "has a console password but no MFA"
  "allows all actions on all resources"
  "can be assumed by any AWS principal"
  "password policy minimum length is 8"
  "does not prevent reuse"
  "does not expire passwords"
)

check() {
  whoami_aws
  local extra_f=() extra_a=()
  [ "$(st_get ACCOUNT_PAB)" = off ] && extra_f+=("has no Block Public Access configuration")
  [ -n "$(st_get SNAPSHOT_ID)" ] && { extra_f+=("is public"); extra_a+=("C-AWS-022|EC2 Snapshot Made Public"); }
  [ -n "$(st_get KMS_KEY)" ] && extra_f+=("has rotation disabled")
  [ -n "$(st_get GD_DETECTOR)" ] && extra_a+=("C-AWS-032|GuardDuty Port Scan Detected")
  [ -z "$(st_get TRAIL)" ] && extra_f+=("No multi-region CloudTrail trail")
  if ! ow_enabled; then
    say "checklist (set OW_URL and OW_USER/OW_PASS or OW_TOKEN to check automatically)"
    echo "Cloud → Accounts and scans → AWS $ACCT: status connected; Event Timeline shows cloud.cloudtrail events"
    echo "Overview → Run Scan, then these findings:"; for f in "${EXPECT_FINDINGS[@]}" "${extra_f[@]}"; do echo "   - …$f…"; done
    echo "Detect → Alerts, these titles (after 'attack' + ~15 min):"; for a in "${EXPECT_ALERTS[@]}" "${extra_a[@]}"; do echo "   - ${a#*|}  (${a%%|*})"; done
    echo "Must NOT appear for ObsidianWatch's own scans: C-RECON alerts whose user agent is ObsidianWatch-connector."
    return
  fi
  ow_login
  local id; id=$(st_get OW_CONNECTOR); [ -n "$id" ] || id=$(ow_connector_id)
  [ -n "$id" ] || die "no AWS connector for account $ACCT in ObsidianWatch (run up with OW_URL set, or add it in the console)"
  local pass=0 wait=0
  row() { if [ "$1" = PASS ]; then pass=$((pass+1)); printf '   \033[32mPASS\033[0m     %s\n' "$2"; else wait=$((wait+1)); printf '   \033[33mNOT YET\033[0m  %s\n' "$2"; fi; }

  say "connector $id: sources"
  local src; src=$(ow GET "/api/v1/cloud-connectors/$id/sources")
  for s in cloudtrail $( [ "$REGION" != us-east-1 ] && echo cloudtrail_global ); do
    local stt; stt=$(echo "$src" | python3 -c "
import json,sys
d=json.load(sys.stdin).get('sources') or []
v=next((x for x in d if x.get('source')=='$s'),None)
print(v['state']+(' - '+v.get('detail','') if v.get('detail') else '') if v else 'not reported yet (wait for a sync)')" 2>/dev/null)
    [ "$stt" = ok ] && row PASS "$s source ok" || row WAIT "$s source: $stt"
  done

  say "posture findings (latest scan)"
  local cspm; cspm=$(ow GET "/api/v1/cloud-connectors/$id/cspm")
  local titles; titles=$(echo "$cspm" | python3 -c "
import json,sys
d=json.load(sys.stdin); r=d.get('result',d)
for f in r.get('findings') or []: print(f.get('title',''))" 2>/dev/null)
  [ -n "$titles" ] || warn "no scan result yet: Overview → Run Scan (or POST /cloud-connectors/$id/cspm)"
  for f in "${EXPECT_FINDINGS[@]}" "${extra_f[@]}"; do
    echo "$titles" | grep -qiF "$f" && row PASS "finding: …$f…" || row WAIT "finding: …$f…"
  done

  say "alerts"
  # one line per alert: "<rule_id>|<title>"; matched on the rule ID, else on the rule name in the title
  local alerts; alerts=$(ow GET "/api/v1/alerts?limit=1000" | python3 -c "
import json,sys
d=json.load(sys.stdin)
if 'error' in d: print('ERROR|'+d['error'])
for a in d.get('alerts') or []: print((a.get('rule_id') or '')+'|'+a.get('title',''))" 2>/dev/null)
  case "$alerts" in ERROR\|*) warn "alerts API: ${alerts#ERROR|}" ;; esac
  for a in "${EXPECT_ALERTS[@]}" "${extra_a[@]}"; do
    if echo "$alerts" | grep -q "^${a%%|*}|" || echo "$alerts" | grep -qiF "${a#*|}"; then row PASS "${a%%|*}  ${a#*|}"; else row WAIT "${a%%|*}  ${a#*|}"; fi
  done
  echo
  echo "$pass passed, $wait not yet. NOT YET right after 'attack' is normal: CloudTrail takes 5-15 minutes, ObsidianWatch syncs"
  echo "every 5. Findings need a scan after 'up' (Overview → Run Scan). Run check again in a few minutes."
}

# ── status / down ────────────────────────────────────────────────────────────────
status() {
  [ -s "$STATE" ] || { echo "nothing created (no state in $STATE_DIR)"; return; }
  say "created by aws-verify.sh (state: $STATE)"
  grep -v -e SECRET -e PASSWORD "$STATE" | sed 's/^/   /'
}

down() {
  whoami_aws
  [ "$(st_get ACCT)" = "" ] || [ "$(st_get ACCT)" = "$ACCT" ] || die "the state belongs to account $(st_get ACCT), you are in $ACCT"
  say "deleting everything aws-verify.sh created in $ACCT"
  if ow_enabled && [ -n "$(st_get OW_CONNECTOR)" ]; then
    ow_login; ow DELETE "/api/v1/cloud-connectors/$(st_get OW_CONNECTOR)" >/dev/null && ok "ObsidianWatch connector $(st_get OW_CONNECTOR) deleted"
  fi
  if [ -n "$(st_get TRAIL)" ]; then
    aws cloudtrail stop-logging --name $P-trail 2>/dev/null; aws cloudtrail delete-trail --name $P-trail 2>/dev/null && ok "trail deleted"
  fi
  for b in "$P-trail-$ACCT-$(st_get REGION)" "$(st_get WEAK_BUCKET)"; do
    [ -n "$b" ] || continue
    aws s3api head-bucket --bucket "$b" >/dev/null 2>&1 || continue
    python3 - "$b" <<'PY'
import json, subprocess, sys
b = sys.argv[1]
while True:
    out = subprocess.run(["aws", "s3api", "list-object-versions", "--bucket", b, "--max-items", "1000", "--output", "json"], capture_output=True, text=True).stdout or "{}"
    d = json.loads(out)
    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in (d.get("Versions") or []) + (d.get("DeleteMarkers") or [])]
    if not objs:
        break
    subprocess.run(["aws", "s3api", "delete-objects", "--bucket", b, "--delete", json.dumps({"Objects": objs, "Quiet": True})], capture_output=True)
PY
    aws s3api delete-bucket --bucket "$b" && ok "bucket $b deleted"
  done
  for k in SG_open-ssh SG_open-all; do local id; id=$(st_get "$k"); [ -n "$id" ] && aws ec2 delete-security-group --group-id "$id" 2>/dev/null && ok "security group $id deleted"; done
  [ -n "$(st_get VPC_ID)" ] && aws ec2 delete-vpc --vpc-id "$(st_get VPC_ID)" 2>/dev/null && ok "VPC deleted"
  [ -n "$(st_get SNAPSHOT_ID)" ] && aws ec2 delete-snapshot --snapshot-id "$(st_get SNAPSHOT_ID)" 2>/dev/null && ok "snapshot deleted"
  [ -n "$(st_get VOLUME_ID)" ] && aws ec2 delete-volume --volume-id "$(st_get VOLUME_ID)" 2>/dev/null && ok "volume deleted"
  [ -n "$(st_get KMS_KEY)" ] && aws kms schedule-key-deletion --key-id "$(st_get KMS_KEY)" --pending-window-in-days 7 >/dev/null 2>&1 && ok "KMS key scheduled for deletion (7 days, not billed meanwhile)"
  [ -n "$(st_get GD_CREATED)" ] && aws guardduty delete-detector --detector-id "$(st_get GD_CREATED)" 2>/dev/null && ok "GuardDuty detector deleted"
  deluser() {
    local u=$1
    aws iam get-user --user-name "$u" >/dev/null 2>&1 || return 0
    aws iam delete-login-profile --user-name "$u" 2>/dev/null
    for k in $(aws iam list-access-keys --user-name "$u" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do aws iam delete-access-key --user-name "$u" --access-key-id "$k"; done
    for p in $(aws iam list-user-policies --user-name "$u" --query PolicyNames --output text); do aws iam delete-user-policy --user-name "$u" --policy-name "$p"; done
    for p in $(aws iam list-attached-user-policies --user-name "$u" --query 'AttachedPolicies[].PolicyArn' --output text); do aws iam detach-user-policy --user-name "$u" --policy-arn "$p"; done
    aws iam delete-user --user-name "$u" && ok "user $u deleted"
  }
  delrole() {
    local r=$1
    aws iam get-role --role-name "$r" >/dev/null 2>&1 || return 0
    for p in $(aws iam list-role-policies --role-name "$r" --query PolicyNames --output text); do aws iam delete-role-policy --role-name "$r" --policy-name "$p"; done
    for p in $(aws iam list-attached-role-policies --role-name "$r" --query 'AttachedPolicies[].PolicyArn' --output text); do aws iam detach-role-policy --role-name "$r" --policy-arn "$p"; done
    aws iam delete-role --role-name "$r" && ok "role $r deleted"
  }
  deluser $P-connector; deluser $P-nomfa
  for u in $(aws iam list-users --query "Users[?starts_with(UserName,'$P-temp-')].UserName" --output text); do deluser "$u"; done
  delrole $P-readonly; delrole $P-open-trust
  aws iam delete-policy --policy-arn "arn:aws:iam::$ACCT:policy/$P-star" 2>/dev/null && ok "policy $P-star deleted"
  if [ -n "$(st_get PWPOLICY_SAVED)" ]; then
    if grep -q '^none' "$STATE_DIR/pwpolicy.json" 2>/dev/null; then
      aws iam delete-account-password-policy 2>/dev/null; ok "password policy removed (there was none before)"
    else
      python3 - "$STATE_DIR/pwpolicy.json" <<'PY' && ok "password policy restored"
import json, subprocess, sys
p = json.load(open(sys.argv[1]))
args = ["aws", "iam", "update-account-password-policy"]
m = {"MinimumPasswordLength": "--minimum-password-length", "MaxPasswordAge": "--max-password-age", "PasswordReusePrevention": "--password-reuse-prevention"}
for k, f in m.items():
    if p.get(k): args += [f, str(p[k])]
for k, on, off in [("RequireSymbols", "--require-symbols", "--no-require-symbols"), ("RequireNumbers", "--require-numbers", "--no-require-numbers"),
                   ("RequireUppercaseCharacters", "--require-uppercase-characters", "--no-require-uppercase-characters"),
                   ("RequireLowercaseCharacters", "--require-lowercase-characters", "--no-require-lowercase-characters"),
                   ("AllowUsersToChangePassword", "--allow-users-to-change-password", "--no-allow-users-to-change-password"),
                   ("HardExpiry", "--hard-expiry", "--no-hard-expiry")]:
    args.append(on if p.get(k) else off)
sys.exit(subprocess.run(args).returncode)
PY
    fi
  fi
  rm -f "$STATE" "$STATE_DIR"/*.json "$STATE_DIR/connector.txt"
  say "done. Secrets Manager secrets were force-deleted when created; nothing else is left."
}

case "${1:-}" in
  up)     shift; up "$@" ;;
  attack) attack ;;
  check)  check ;;
  status) status ;;
  down)   down ;;
  *)      sed -n '2,32p' "$0"; exit 1 ;;
esac
