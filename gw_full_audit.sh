#!/usr/bin/env bash
# Google Workspace Full Health-Check – v2
# Usage: ./gw_full_audit_v2.sh <CUSTOMER_ID|my_customer> <PRIMARY_DOMAIN> <ADMIN_EMAIL>

set -euo pipefail

CUST_ID="$1"          # e.g. my_customer
PRIMARY_DOMAIN="$2"   # e.g. example.org
ADMIN_EMAIL="$3"      # super-admin to impersonate

SA_KEY_JSON="$HOME/audit-sa-key.json"   # JSON key for the service account
REPORT_DIR="gw-reports"
mkdir -p "$REPORT_DIR"

########################################################################
# 1. OAuth2 – domain-wide delegated token with auto-refresh
########################################################################
TOKEN="" ; TOKEN_TS=0
get_token () {
  local now=$(date +%s)
  # refresh 60 s before the 1-h default expiry
  if (( now - TOKEN_TS < 3300 )) && [[ -n "$TOKEN" ]]; then return; fi
  TOKEN=$(oauth2l fetch --json "$SA_KEY_JSON" --jwt --email "$ADMIN_EMAIL" --scope "
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
https://www.googleapis.com/auth/admin.directory.orgunit.readonly
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
https://www.googleapis.com/auth/admin.directory.user.security
https://www.googleapis.com/auth/admin.reports.usage.readonly
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/apps.alerts
https://www.googleapis.com/auth/gmail.settings.basic
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/chrome.management.policy.readonly
https://www.googleapis.com/auth/apps.groups.settings
https://www.googleapis.com/auth/ediscovery.readonly")
  TOKEN_TS=$now
}

########################################################################
# 2. Safe CURL + pagination helpers
########################################################################
api () {           # api <url> [json_data_for_POST]
  get_token
  local url="$1" ; shift || true
  local body flag
  if [[ $# -gt 0 ]]; then
    flag=(-X POST -H "Content-Type: application/json" -d "$1")
  else
    flag=()
  fi
  resp=$(curl -sS -w 'HTTPCODE:%{http_code}' \
         -H "Authorization: Bearer $TOKEN" \
         -H "Accept: application/json" "${flag[@]}" "$url")
  code="${resp##*HTTPCODE:}" ; body="${resp%%HTTPCODE:*}"
  [[ "$code" == "200" ]] || { echo "ERR $code $url" >&2; echo '{}'; }
  printf '%s' "$body"
}

fetch_all () {     # fetch_all <url> > outfile.json
  local url="$1" next data
  printf '['
  while [[ -n "$url" ]]; do
    data=$(api "$url")
    printf '%s%s' "$([ "$url" != "$1" ] && echo ',')" \
           "$(jq -c '.users // .groups // .devices // .alerts // .items // .usageReports // .organizationUnits // .drives // .' <<<"$data")"
    next=$(jq -r '.nextPageToken // empty' <<<"$data")
    [[ -n "$next" ]] && url="${url%%\?*}?$(grep -o '^[^?]*' <<<"$url" | sed 's/$/?/')pageToken=${next}" || url=""
    sleep 0.2   # public rate-limit 5 req/s
  done
  printf ']\n'
}

stamp=$(date +%F_%H%M%S)
today=$(date +%F)

########################################################################
# 3. DATA COLLECTION
########################################################################

echo "• Users"
fetch_all "https://admin.googleapis.com/admin/directory/v1/users?customer=${CUST_ID}&maxResults=500" \
  > "$REPORT_DIR/users_${stamp}.json"

echo "• Groups"
fetch_all "https://admin.googleapis.com/admin/directory/v1/groups?customer=${CUST_ID}&maxResults=500" \
  > "$REPORT_DIR/groups_${stamp}.json"

echo "• Org Units"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/orgunits?type=all" \
  | jq '.organizationUnits' > "$REPORT_DIR/orgunits_${stamp}.json"

echo "• Admin roles & assignments"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/roles" \
  | jq '.items' > "$REPORT_DIR/admin_roles_${stamp}.json"
fetch_all "https://admin.googleapis.com/admin/directory/v1/roleassignments?customer=${CUST_ID}&maxResults=200" \
  > "$REPORT_DIR/role_assignments_${stamp}.json"

echo "• MFA status"
api "https://admin.googleapis.com/admin/reports/v1/usage/dates/${today}?customerId=${CUST_ID}&parameters=accounts:2sv_enrolled" \
  | jq '.usageReports' > "$REPORT_DIR/mfa_${stamp}.json"

echo "• Storage"
api "https://admin.googleapis.com/admin/reports/v1/usage/dates/${today}?customerId=${CUST_ID}&parameters=gmail:num_emails_total,drive:total_bytes,photos:total_bytes" \
  | jq '.usageReports[0].parameters' > "$REPORT_DIR/storage_${stamp}.json"

echo "• Drive external-sharing counts"
api "https://admin.googleapis.com/admin/reports/v1/usage/dates/${today}?customerId=${CUST_ID}&parameters=drive:num_items_shared_outside_domain" \
  | jq '.usageReports' > "$REPORT_DIR/drive_sharing_${stamp}.json"

echo "• Shared drives"
fetch_all "https://www.googleapis.com/drive/v3/drives?pageSize=100" \
  > "$REPORT_DIR/shared_drives_${stamp}.json"

echo "• ChromeOS devices"
fetch_all "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/devices/chromeos?maxResults=200" \
  > "$REPORT_DIR/chromeos_${stamp}.json"

echo "• Alert Center"
fetch_all "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=100" \
  > "$REPORT_DIR/alerts_${stamp}.json"

echo "• Vault matters / holds"
api "https://vault.googleapis.com/v1/matters" \
  | jq '.matters' > "$REPORT_DIR/vault_matters_${stamp}.json"

echo "• Chrome browser policies by OU"
jq -r '.[].orgUnitPath' "$REPORT_DIR/orgunits_${stamp}.json" | while read -r ou; do
  enc=$(jq -rn --arg s "$ou" '$s|@uri')
  req='{"policySchemaFilter":"chrome.users.*","pageSize":300}'
  api "https://chromepolicy.googleapis.com/v1/customers/${CUST_ID}/policies/orgunits/${enc}:resolve" "$req" \
    > "$REPORT_DIR/browser_policy_${ou//\//_}_${stamp}.json"
done

echo "• Gmail per-user forwarding & settings"
jq -r '.[].primaryEmail' "$REPORT_DIR/users_${stamp}.json" | while read -r usr; do
  api "https://gmail.googleapis.com/gmail/v1/users/${usr}/settings/forwardingAddresses" \
    > "$REPORT_DIR/gmail_forward_${usr//[@.]/_}_${stamp}.json"
  api "https://gmail.googleapis.com/gmail/v1/users/${usr}/settings" \
    > "$REPORT_DIR/gmail_settings_${usr//[@.]/_}_${stamp}.json"
done

echo "Done – JSON reports in $REPORT_DIR/"
