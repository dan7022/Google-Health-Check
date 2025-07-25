#!/usr/bin/env bash
# Google Workspace Audit Script
# Usage: ./gw_full_audit.sh <CUSTOMER_ID> <PRIMARY_DOMAIN> <ADMIN_EMAIL>

set -euo pipefail

CUST_ID="$1"
PRIMARY_DOMAIN="$2"
ADMIN_EMAIL="$3"
stamp=$(date +%F_%H%M%S)
mkdir -p gw-reports

# Token handler
get_token() {
  if [[ -n "${IMPERSONATE_SERVICE_ACCOUNT:-}" ]]; then
    gcloud auth application-default print-access-token \
      --impersonate-service-account="$IMPERSONATE_SERVICE_ACCOUNT"
  else
    gcloud auth application-default print-access-token
  fi
}
TOKEN=$(get_token)
api() { curl -sS -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/json" "$1"; }

# USERS
echo "• Users"
api "https://admin.googleapis.com/admin/directory/v1/users?customer=${CUST_ID}&maxResults=500" \
  | jq '.users' > gw-reports/users_${stamp}.json

# GROUPS
echo "• Groups"
api "https://admin.googleapis.com/admin/directory/v1/groups?customer=${CUST_ID}&maxResults=500" \
  | jq '.groups' > gw-reports/groups_${stamp}.json

# ORG UNITS
echo "• Org Units"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/orgunits?type=all" \
  | jq '.organizationUnits' > gw-reports/orgunits_${stamp}.json

# ADMIN ROLES & ASSIGNMENTS
echo "• Admin Roles"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/roles" \
  | jq '.items' > gw-reports/admin_roles_${stamp}.json
api "https://admin.googleapis.com/admin/directory/v1/roleassignments?customer=${CUST_ID}" \
  | jq '.items' > gw-reports/role_assignments_${stamp}.json

# MFA & 2SV
echo "• MFA Status"
today=$(date +%F)
api "https://admin.googleapis.com/admin/reports/v1/usage/users/all/dates/${today}?parameters=accounts:2sv_enrolled" \
  | jq '.usageReports' > gw-reports/mfa_${stamp}.json

# DRIVE & GMAIL STORAGE USAGE
echo "• Storage"
api "https://admin.googleapis.com/admin/reports/v1/usage/customers/dates/${today}?parameters=gmail:num_emails_total,drive:total_bytes,photos:total_bytes" \
  | jq '.usageReports[0].parameters' > gw-reports/storage_${stamp}.json

# DRIVE SHARING
echo "• Drive External Sharing"
api "https://admin.googleapis.com/admin/reports/v1/usage/users/all/dates/${today}?parameters=drive:num_items_shared_outside_domain" \
  | jq '.usageReports' > gw-reports/drive_sharing_${stamp}.json

# GMAIL FORWARDING
echo "• Gmail Forwarding (per user)"
jq -r '.[].primaryEmail' gw-reports/users_${stamp}.json | while read -r usr; do
  api "https://gmail.googleapis.com/gmail/v1/users/${usr}/settings/forwardingAddresses" \
    > "gw-reports/gmail_forward_${usr//[@.]/_}_${stamp}.json"
done

# ALERT CENTER
echo "• Alert Center"
api "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=100" \
  | jq '.alerts' > gw-reports/alerts_${stamp}.json

# CHROME DEVICE SETTINGS
echo "• ChromeOS Devices"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/devices/chromeos?maxResults=200" \
  | jq '.devices' > gw-reports/chromeos_${stamp}.json

# CHROME BROWSER SETTINGS (per OU)
echo "• Chrome Browser Settings"
oulist=$(jq -r '.[].orgUnitPath' gw-reports/orgunits_${stamp}.json)
for ou in $oulist; do
  enc_ou=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${ou}'''))")
  api "https://chromepolicy.googleapis.com/v1/customers/${CUST_ID}/policies/orgunits/${enc_ou}:resolve?policySchemaFilter=chrome.users.*" \
    | jq '.' > "gw-reports/browser_policy_${ou//\//_}_${stamp}.json"
done

# VAULT RETENTION POLICIES
echo "• Vault Retention Rules"
api "https://vault.googleapis.com/v1/matters" \
  | jq '.' > gw-reports/vault_matters_${stamp}.json

# GMAIL SETTINGS (basic per user)
echo "• Gmail Settings (per user)"
jq -r '.[].primaryEmail' gw-reports/users_${stamp}.json | while read -r usr; do
  api "https://gmail.googleapis.com/gmail/v1/users/${usr}/settings" \
    > "gw-reports/gmail_settings_${usr//[@.]/_}_${stamp}.json"
done

# DRIVE SHARED DRIVES
echo "• Shared Drives"
api "https://www.googleapis.com/drive/v3/drives?pageSize=100" \
  | jq '.drives' > gw-reports/shared_drives_${stamp}.json

echo "Done. Output saved in gw-reports/"
