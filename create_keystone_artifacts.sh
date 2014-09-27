#   Copyright 2013-2014 STACKOPS TECHNOLOGIES S.L.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#!/usr/bin/env bash

set -e
set -o nounset                              # Treat unset variables as an error

KEYSTONE_URL=$1
OS_USERNAME=admin
OS_PASSWORD=$2
OS_TENANT_ADMIN_NAME=admin

if ! type "keystone" > /dev/null; then
    echo "keystone command line tool not installed. This script needs it. Bye!"
    exit 1
fi

KEYSTONE_CMD="keystone --os-auth-url $KEYSTONE_URL --os-username $OS_USERNAME --os-password $OS_PASSWORD --os-tenant-name $OS_TENANT_ADMIN_NAME --insecure"

# Get the tenant Id
get_tenant_id()
{
    echo "`$KEYSTONE_CMD tenant-list | grep "$1" | awk '/ | / { print $2 }' | head -n 1`"
}

# Get the role Id
get_role_id()
{
    echo "`$KEYSTONE_CMD role-list | grep $1 | awk '/ | / { print $2 }' | head -n 1`"
}

# Create role
create_role()
{
    echo "`$KEYSTONE_CMD role-create --name=$1 | grep id | awk '/ | / { print $4 }' | head -n 1`"
}

# Get the user Id
get_user_id()
{
    echo "`$KEYSTONE_CMD user-list | grep $1 | awk '/ | / { print $2 }' | head -n 1`"
}

# Bind user to role with tenant
bind_user_role_tenant()
{
    echo "`$KEYSTONE_CMD user-role-add --user-id $1 --role-id $2 --tenant-id $3`"
}

create_service()
{
    service_id=`$KEYSTONE_CMD service-create --name=$1 --type=$2 --description="$3" | awk '/ id / { print $4 }' `
    $KEYSTONE_CMD endpoint-create --region $4 --service-id $service_id --publicurl "$5" --adminurl "$6" --internalurl "$7"
}


# Get auth token
get_auth_token()
{
    credentials=`curl -s -d "{\"auth\":{\"passwordCredentials\": {\"username\": \"$OS_USERNAME\", \"password\": \"$OS_PASSWORD\"}, \"tenantName\": \"$1\"}}" -H "Content-type: application/json" https://$KEYSTONE_HOST/v2.0/tokens`
    echo `echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['access']['token']['id'];"`
}

ROLE_ADMIN=`get_role_id admin`
ROLE_ACCOUNTING=`get_role_id ROLE_ACCOUNTING`
ROLE_ACTIVITY=`get_role_id ROLE_ACTIVITY`
ROLE_ACTIVITY_ADMIN=`get_role_id ROLE_ACTIVITY_ADMIN`
ROLE_CHARGEBACK=`get_role_id ROLE_CHARGEBACK`
ROLE_CHARGEBACK_ADMIN=`get_role_id ROLE_CHARGEBACK_ADMIN`
ROLE_PORTAL_ADMIN=`get_role_id ROLE_PORTAL_ADMIN`
ROLE_PORTAL_USER=`get_role_id ROLE_PORTAL_USER`

USER_ADMIN_ID=`get_user_id admin`
ADMIN_TENANT_ID=`get_tenant_id admin`

if [ ! -z "${ROLE_ADMIN}" ]; then
    echo "ROLE_ADMIN_ID: $ROLE_ADMIN"
else
    echo "admin role does not exists"
fi

if [ ! -z "${ROLE_PORTAL_ADMIN}" ]; then
    echo "ROLE_PORTAL_ADMIN ID: $ROLE_PORTAL_ADMIN"
else
    echo "ROLE_PORTAL_ADMIN role does not exists. Creating."
    ROLE_PORTAL_ADMIN=`create_role ROLE_PORTAL_ADMIN`
    echo "ROLE_PORTAL_ADMIN ID: $ROLE_PORTAL_ADMIN"
fi

if [ ! -z "${ROLE_PORTAL_USER}" ]; then
    echo "ROLE_PORTAL_USER ID: $ROLE_PORTAL_USER"
else
    echo "ROLE_PORTAL_USER role does not exists. Creating."
    ROLE_PORTAL_USER=`create_role ROLE_PORTAL_USER`
    echo "ROLE_PORTAL_USER ID: $ROLE_PORTAL_USER"
fi

if [ ! -z "${ROLE_ACCOUNTING}" ]; then
    echo "ROLE_ACCOUNTING ID: $ROLE_ACCOUNTING"
else
       echo "ROLE_ACCOUNTING role does not exists. Creating."
    ROLE_ACCOUNTING=`create_role ROLE_ACCOUNTING`
    echo "ROLE_ACCOUNTING ID: $ROLE_ACCOUNTING"
fi

if [ ! -z "${ROLE_ACTIVITY}" ]; then
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY"
    echo "ROLE_ACTIVITY role does not exists. Creating."
else
    ROLE_ACTIVITY=`create_role ROLE_ACTIVITY`
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY"
fi

if [ ! -z "${ROLE_ACTIVITY_ADMIN}" ]; then
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY_ADMIN"
else
    echo "ROLE_ACTIVITY_ADMIN role does not exists. Creating."
    ROLE_ACTIVITY_ADMIN=`create_role ROLE_ACTIVITY_ADMIN`
    echo "ROLE_ACTIVITY_ADMIN ID: $ROLE_ACTIVITY_ADMIN"
fi

if [ ! -z "${ROLE_CHARGEBACK}" ]; then
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK"
else
    echo "ROLE_CHARGEBACK role does not exists. Creating."
    ROLE_CHARGEBACK=`create_role ROLE_CHARGEBACK`
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK"
fi

if [ ! -z "${ROLE_CHARGEBACK_ADMIN}" ]; then
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK_ADMIN"
else
    echo "ROLE_CHARGEBACK_ADMIN role does not exists. Creating."
    ROLE_CHARGEBACK_ADMIN=`create_role ROLE_CHARGEBACK_ADMIN`
    echo "ROLE_CHARGEBACK_ADMIN ID: $ROLE_CHARGEBACK_ADMIN"
fi

echo "USER admin ID: $USER_ADMIN_ID"
echo "TENANT admin ID: $ADMIN_TENANT_ID"

OK=`bind_user_role_tenant $USER_ADMIN_ID $ROLE_PORTAL_ADMIN $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $USER_ADMIN_ID $ROLE_PORTAL_USER $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $USER_ADMIN_ID $ROLE_ACCOUNTING $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $USER_ADMIN_ID $ROLE_ACTIVITY $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $USER_ADMIN_ID $ROLE_ACTIVITY_ADMIN $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $USER_ADMIN_ID $ROLE_CHARGEBACK $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $USER_ADMIN_ID $ROLE_CHARGEBACK_ADMIN $ADMIN_TENANT_ID`

create_service activity activity "activity" RegionOne "http://localhost:8080/activity" "" "http://localhost:8080/activity"
create_service activity activity "accounting" RegionOne "http://localhost:8080/accounting" "" "http://localhost:8080/accounting"
create_service activity activity "chargeback" RegionOne "http://localhost:8080/chargeback" "" "http://localhost:8080/chargeback"
