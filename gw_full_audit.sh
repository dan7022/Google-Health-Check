#!/usr/bin/env bash
# Google Workspace Health-Check Collector (read-only)
# Usage: ./gw_full_audit.sh <CUSTOMER_ID> <PRIMARY_DOMAIN> <ADMIN_EMAIL>

set -euo pipefail

CUST_ID="$1"        # e.g. C02pwov7k
PRIMARY_DOMAIN="$2" # e.g. aisne.org
ADMIN_EMAIL="$3"    # e.g. securewon@aisne.org

stamp=$(date +%F_%H%M%S)
mkdir -p gw-reports

########################################################################
# 1) ACCESS-TOKEN HANDLING (domain-wide delegation via oauth2l)
########################################################################
SA_KEY_JSON="$HOME/audit-sa-key.json"          # path to your service-account key file

get_token() {
  oauth2l fetch --json "$SA_KEY_JSON" \
      --jwt --email "$ADMIN_EMAIL" \
      --scope "
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
https://www.googleapis.com/auth/admin.reports.usage.readonly
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/admin.directory.orgunit.readonly
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
https://www.googleapis.com/auth/admin.directory.user.security
https://www.googleapis.com/auth/apps.alerts
https://www.googleapis.com/auth/gmail.settings.basic
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/chrome.management.policy.readonly
https://www.googleapis.com/auth/apps.groups.settings"
}

TOKEN=$(get_token)   # <<<—  needed by api()

########################################################################
# 2) CURL WRAPPER – never passes HTML to jq
########################################################################
api() {
  url="$1"
  resp="$(curl -sS -w 'HTTPCODE:%{http_code}' \
          -H "Authorization: Bearer ${TOKEN}" \
          -H "Accept: application/json" "${url}")"

  body="${resp%%HTTPCODE:*}"
  code="${resp##*HTTPCODE:}"

  if [[ "$code" != "200" ]]; then
    echo "ERROR $code → $url" >&2
    echo '{}'           # safe empty JSON
  else
    printf '%s' "$body"
  fi
}

today=$(date +%F)

########################################################################
# 3) DATA COLLECTION
########################################################################

echo "• Users"
api "https://admin.googleapis.com/admin/directory/v1/users?customer=${CUST_ID}&maxResults=500" \
  | jq '.users // []' > "gw-reports/users_${stamp}.json"

echo "• Groups"
api "https://admin.googleapis.com/admin/directory/v1/groups?customer=${CUST_ID}&maxResults=500" \
  | jq '.groups // []' > "gw-reports/groups_${stamp}.json"

echo "• Org Units"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/orgunits?type=all" \
  | jq '.organizationUnits // []' > "gw-reports/orgunits_${stamp}.json"

echo "• Admin Roles"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/roles" \
  | jq '.items // []' > "gw-reports/admin_roles_${stamp}.json"

api "https://admin.googleapis.com/admin/directory/v1/roleassignments?customer=${CUST_ID}&maxResults=200" \
  | jq '.items // []' > "gw-reports/role_assignments_${stamp}.json"

echo "• MFA Status"
api "https://admin.googleapis.com/admin/reports/v1/usage/dates/${today}?customerId=${CUST_ID}&parameters=accounts:2sv_enrolled" \
  | jq '.usageReports // []' > "gw-reports/mfa_${stamp}.json"

echo "• Storage"
api "https://admin.googleapis.com/admin/reports/v1/usage/dates/${today}?customerId=${CUST_ID}&parameters=gmail:num_emails_total,drive:total_bytes,photos:total_bytes" \
  | jq '.usageReports[0].parameters // {}' > "gw-reports/storage_${stamp}.json"

echo "• Drive External Sharing"
api "https://admin.googleapis.com/admin/reports/v1/usage/dates/${today}?customerId=${CUST_ID}&parameters=drive:num_items_shared_outside_domain" \
  | jq '.usageReports // []' > "gw-reports/drive_sharing_${stamp}.json"

echo "• Gmail Forwarding (per-user)"
jq -r '.[].primaryEmail' "gw-reports/users_${stamp}.json" | while read -r usr; do
  api "https://gmail.googleapis.com/gmail/v1/users/${usr}/settings/forwardingAddresses" \
    > "gw-reports/gmail_forward_${usr//[@.]/_}_${stamp}.json"
done

echo "• Alert Center"
api "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=100" \
  | jq '.alerts // []' > "gw-reports/alerts_${stamp}.json"

echo "• ChromeOS Devices"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/devices/chromeos?maxResults=200" \
  | jq '.devices // []' > "gw-reports/chromeos_${stamp}.json"

echo "• Chrome Browser Policies by OU"
jq -r '.[].orgUnitPath' "gw-reports/orgunits_${stamp}.json" | while read -r ou; do
  enc="$(python3 - <<EOF
import urllib.parse, os, sys
print(urllib.parse.quote(os.environ["OU"]))
EOF
OU="$ou"
)"
  api "https://chromepolicy.googleapis.com/v1/customers/${CUST_ID}/policies/orgunits/${enc}:resolve?policySchemaFilter=chrome.users.*" \
    | jq '.' > "gw-reports/browser_policy_${ou//\//_}_${stamp}.json"
done

echo "• Vault Matters"
api "https://vault.googleapis.com/v1/matters" \
  | jq '.' > "gw-reports/vault_matters_${stamp}.json"

echo "• Gmail Settings (per-user)"
jq -r '.[].primaryEmail' "gw-reports/users_${stamp}.json" | while read -r usr; do
  api "https://gmail.googleapis.com/gmail/v1/users/${usr}/settings" \
    > "gw-reports/gmail_settings_${usr//[@.]/_}_${stamp}.json"
done

echo "• Shared Drives"
api "https://www.googleapis.com/drive/v3/drives?pageSize=100" \
  | jq '.drives // []' > "gw-reports/shared_drives_${stamp}.json"

echo "Done – reports saved in ./gw-reports/"
