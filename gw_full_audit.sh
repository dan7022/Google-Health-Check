#!/usr/bin/env bash
# Google Workspace Audit Script (Read-Only)
# Usage: ./gw_full_audit.sh <CUSTOMER_ID> <PRIMARY_DOMAIN> <ADMIN_EMAIL>
# Requires: gcloud CLI, either a service account key OR impersonation setup

set -euo pipefail

CUST_ID="$1"          # e.g. C0123456
PRIMARY_DOMAIN="$2"   # e.g. example.com
ADMIN_EMAIL="$3"      # e.g. admin@example.com

# Get the access token
get_token() {
  # Prefer impersonation if configured
  if [[ -n "${IMPERSONATE_SERVICE_ACCOUNT:-}" ]]; then
    gcloud auth application-default print-access-token \
      --impersonate-service-account="$IMPERSONATE_SERVICE_ACCOUNT"
  else
    gcloud auth application-default print-access-token
  fi
}

# Simple GET wrapper
api() {
  curl -sS -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/json" "$1"
}

# Prep
stamp=$(date +%F_%H%M%S)
mkdir -p gw-reports
TOKEN=$(get_token)

# --- USERS ---
echo "• Users"
api "https://admin.googleapis.com/admin/directory/v1/users?customer=${CUST_ID}&maxResults=500&fields=users(id,email,suspended,lastLoginTime)" \
  | jq '.users' > gw-reports/users_${stamp}.json

# --- ADMIN ROLES ---
echo "• Admin Roles"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/roles?maxResults=200" \
  | jq '.items' > gw-reports/admin_roles_${stamp}.json

api "https://admin.googleapis.com/admin/directory/v1/roleassignments?customer=${CUST_ID}&maxResults=200" \
  | jq '.items' > gw-reports/role_assignments_${stamp}.json

# --- MFA STATUS ---
echo "• MFA Status"
today=$(date +%F)
api "https://admin.googleapis.com/admin/reports/v1/usage/users/all/dates/${today}?parameters=accounts:2sv_enrolled" \
  | jq '.usageReports' > gw-reports/mfa_${stamp}.json

# --- STORAGE ---
echo "• Storage"
api "https://admin.googleapis.com/admin/reports/v1/usage/customers/dates/${today}?parameters=gmail:num_emails_total,drive:total_bytes,photos:total_bytes" \
  | jq '.usageReports[0].parameters' > gw-reports/storage_${stamp}.json

# --- ORG UNITS ---
echo "• Org Units"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/orgunits?type=all" \
  | jq '.organizationUnits' > gw-reports/orgunits_${stamp}.json

# --- GROUPS ---
echo "• Groups"
api "https://admin.googleapis.com/admin/directory/v1/groups?customer=${CUST_ID}&maxResults=500" \
  | jq '.groups' > gw-reports/groups_${stamp}.json

# --- CHROME OS DEVICES ---
echo "• ChromeOS Devices"
api "https://admin.googleapis.com/admin/directory/v1/customer/${CUST_ID}/devices/chromeos?maxResults=200" \
  | jq '.devices' > gw-reports/chromeos_${stamp}.json

# --- DRIVE SHARING ---
echo "• Drive Sharing"
api "https://admin.googleapis.com/admin/reports/v1/usage/users/all/dates/${today}?parameters=drive:num_items_shared_outside_domain" \
  | jq '.usageReports' > gw-reports/drive_sharing_${stamp}.json

# --- FORWARDING RULES (optional, slow for large orgs) ---
echo "• Gmail Forwarding (per user)"
jq -r '.[].email' gw-reports/users_${stamp}.json | while read -r usr; do
  api "https://gmail.googleapis.com/gmail/v1/users/${usr}/settings/forwardingAddresses" \
    > "gw-reports/gmail_forward_${usr//[@.]/_}_${stamp}.json"
done

# --- ALERTS (optional) ---
echo "• Alert Center"
api "https://alertcenter.googleapis.com/v1beta1/alerts?pageSize=100" \
  | jq '.alerts' > gw-reports/alerts_${stamp}.json

echo "Done. Reports saved to ./gw-reports/"
