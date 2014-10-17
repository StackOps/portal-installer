
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

set -x

KEYSTONE_URL=$1
OS_USERNAME=admin
OS_PASSWORD=$2
OS_TENANT_ADMIN_NAME=admin
OS_AUTH_URL=$KEYSTONE_URL

if ! type "curl" > /dev/null; then
    echo "curl command line tool not installed. This script needs it. Bye!"
    exit 1
fi

# Get the tenant Id
get_tenant_id()
{
    credentials=`curl -s $OS_AUTH_URL/tenants -H "X-Auth-Token:$1" -H "Content-type: application/json"`
    result=""
    set +e
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print [d for d in tok['tenants'] if d['name'] == '$2'][0]['id'] "`
    set -e
    echo $result
}

# Get the role Id
get_role_id() {
    credentials=`curl -s $OS_AUTH_URL/OS-KSADM/roles -H "X-Auth-Token:$1" -H "Content-type: application/json"`
    result=""
    set +e
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print [d for d in tok['roles'] if d['name'] == '$2'][0]['id']" 2> /dev/null`
    set -e
    echo $result
}

# Create role
create_role()
{
    credentials=`curl -s $OS_AUTH_URL/OS-KSADM/roles -X POST -H "X-Auth-Token:$1" -H "Content-type: application/json" -d "{\"role\": {\"name\": \"$2\"}}"`
    result=""
    set +e
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['role']['id'] "`
    set -e
    echo $result
}

# Create role
create_user()
{
    credentials=`curl -s $OS_AUTH_URL/users -X POST -H "X-Auth-Token:$1" -H "Content-type: application/json" -d "{\"user\": {\"email\": null, \"password\": \"$4\", \"enabled\": true, \"name\": \"$2\", \"tenantId\": \"$3\"}}"`
    result=""
    set +e
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['user']['id'] "`
    set -e
    echo $result
}

# Get the user Id
get_user_id()
{
    credentials=`curl -s $OS_AUTH_URL/users -H "X-Auth-Token:$1" -H "Content-type: application/json"`
    result=""
    set +e
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print [d for d in tok['users'] if d['name'] == '$2'][0]['id'] "`
    set -e
    echo $result
}

# Bind user to role with tenant
bind_user_role_tenant()
{
    credentials=`curl -s $OS_AUTH_URL/tenants/$4/users/$2/roles/OS-KSADM/$3 -X PUT -H "X-Auth-Token:$1" -H "Content-type: application/json"`
    result=""
    set +e
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print 'error' in tok "`
    if [ "$result" == "True" ]; then
        result=""
    else
        result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['role']['id'] "`
    fi
    set -e
    echo $result
}

create_service()
{
    credentials=`curl -s $OS_AUTH_URL/OS-KSADM/services -X POST -H "X-Auth-Token:$1" -H "Content-type: application/json" -d "{\"OS-KSADM:service\": {\"type\":\"$3\", \"name\": \"$2\", \"description\": \"$4\"}}"`
    service_id=""
    set +e
    service_id=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['OS-KSADM:service']['id'] "`
    set -e
    credentials=`curl -s $OS_AUTH_URL/endpoints -X POST -H "X-Auth-Token:$1" -H "Content-type: application/json" -d "{\"endpoint\": {\"adminurl\": \"$7\", \"service_id\": \"$service_id\", \"region\": \"$5\", \"internalurl\": \"$8\", \"publicurl\": \"$6\"}}"`
}

get_service_id()
{
    credentials=`curl -s $OS_AUTH_URL/OS-KSADM/services -H "X-Auth-Token:$1" -H "Content-type: application/json"`
    result=""
    set +e
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print [d for d in tok['OS-KSADM:services'] if d['name'] == '$2'][0]['id'] "`
    set -e
    echo $result
}

# Get auth token
get_auth_token()
{
    credentials=`curl -s -d "{\"auth\":{\"passwordCredentials\": {\"username\": \"$OS_USERNAME\", \"password\": \"$OS_PASSWORD\"}, \"tenantName\": \"$1\"}}" -H "Content-type: application/json" $OS_AUTH_URL/tokens`
    echo `echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['access']['token']['id'];"`
}

auth_token=`get_auth_token $OS_TENANT_ADMIN_NAME`
ROLE_ADMIN=`get_role_id $auth_token adminx`

exit 1

ROLE_ACCOUNTING=`get_role_id $auth_token ROLE_ACCOUNTING`
ROLE_ACTIVITY=`get_role_id $auth_token ROLE_ACTIVITY`
ROLE_ACTIVITY_ADMIN=`get_role_id $auth_token ROLE_ACTIVITY_ADMIN`
ROLE_CHARGEBACK=`get_role_id $auth_token ROLE_CHARGEBACK`
ROLE_CHARGEBACK_ADMIN=`get_role_id $auth_token ROLE_CHARGEBACK_ADMIN`
ROLE_PORTAL_ADMIN=`get_role_id $auth_token ROLE_PORTAL_ADMIN`
ROLE_PORTAL_USER=`get_role_id $auth_token ROLE_PORTAL_USER`

USER_ADMIN_ID=`get_user_id $auth_token admin`
ADMIN_TENANT_ID=`get_tenant_id $auth_token admin`

if [ ! -z "${ROLE_ADMIN}" ]; then
    echo "ROLE_ADMIN_ID: $ROLE_ADMIN"
else
    echo "admin role does not exists. There is something wrong in your OpenStack installation."
    exit  1
fi

if [ ! -z "${ROLE_PORTAL_ADMIN}" ]; then
    echo "ROLE_PORTAL_ADMIN ID: $ROLE_PORTAL_ADMIN"
else
    echo "ROLE_PORTAL_ADMIN role does not exists. Creating."
    ROLE_PORTAL_ADMIN=`create_role  $auth_token ROLE_PORTAL_ADMIN`
    echo "ROLE_PORTAL_ADMIN ID: $ROLE_PORTAL_ADMIN"
fi

if [ ! -z "${ROLE_PORTAL_USER}" ]; then
    echo "ROLE_PORTAL_USER ID: $ROLE_PORTAL_USER"
else
    echo "ROLE_PORTAL_USER role does not exists. Creating."
    ROLE_PORTAL_USER=`create_role  $auth_token ROLE_PORTAL_USER`
    echo "ROLE_PORTAL_USER ID: $ROLE_PORTAL_USER"
fi

if [ ! -z "${ROLE_ACCOUNTING}" ]; then
    echo "ROLE_ACCOUNTING ID: $ROLE_ACCOUNTING"
else
    echo "ROLE_ACCOUNTING role does not exists. Creating."
    ROLE_ACCOUNTING=`create_role  $auth_token ROLE_ACCOUNTING`
    echo "ROLE_ACCOUNTING ID: $ROLE_ACCOUNTING"
fi

if [ ! -z "${ROLE_ACTIVITY}" ]; then
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY"
else
    echo "ROLE_ACTIVITY role does not exists. Creating."
    ROLE_ACTIVITY=`create_role $auth_token ROLE_ACTIVITY`
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY"
fi

if [ ! -z "${ROLE_ACTIVITY_ADMIN}" ]; then
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY_ADMIN"
else
    echo "ROLE_ACTIVITY_ADMIN role does not exists. Creating."
    ROLE_ACTIVITY_ADMIN=`create_role  $auth_token ROLE_ACTIVITY_ADMIN`
    echo "ROLE_ACTIVITY_ADMIN ID: $ROLE_ACTIVITY_ADMIN"
fi

if [ ! -z "${ROLE_CHARGEBACK}" ]; then
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK"
else
    echo "ROLE_CHARGEBACK role does not exists. Creating."
    ROLE_CHARGEBACK=`create_role  $auth_token ROLE_CHARGEBACK`
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK"
fi

if [ ! -z "${ROLE_CHARGEBACK_ADMIN}" ]; then
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK_ADMIN"
else
    echo "ROLE_CHARGEBACK_ADMIN role does not exists. Creating."
    ROLE_CHARGEBACK_ADMIN=`create_role  $auth_token ROLE_CHARGEBACK_ADMIN`
    echo "ROLE_CHARGEBACK_ADMIN ID: $ROLE_CHARGEBACK_ADMIN"
fi

echo "USER admin ID: $USER_ADMIN_ID"
echo "TENANT admin ID: $ADMIN_TENANT_ID"

OK=`bind_user_role_tenant $auth_token $USER_ADMIN_ID $ROLE_PORTAL_ADMIN $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $auth_token $USER_ADMIN_ID $ROLE_PORTAL_USER $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $auth_token $USER_ADMIN_ID $ROLE_ACCOUNTING $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $auth_token $USER_ADMIN_ID $ROLE_ACTIVITY $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $auth_token $USER_ADMIN_ID $ROLE_ACTIVITY_ADMIN $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $auth_token $USER_ADMIN_ID $ROLE_CHARGEBACK $ADMIN_TENANT_ID`
OK=`bind_user_role_tenant $auth_token $USER_ADMIN_ID $ROLE_CHARGEBACK_ADMIN $ADMIN_TENANT_ID`

OK=`get_service_id $auth_token "activity"`
if [ "${OK}" != "" ]; then
    echo "Activity service already exists."
else
    create_service $auth_token activity activity "activity" RegionOne "http://localhost:8080/activity" "" "http://localhost:8080/activity"
    echo "Activity service created."
fi

OK=`get_service_id $auth_token "accounting"`
if [ "${OK}" != "" ]; then
    echo "Accounting service already exists."
else
    create_service $auth_token accounting accounting "accounting" RegionOne "http://localhost:8080/activity" "" "http://localhost:8080/activity"
    echo "Accounting service created."
fi

OK=`get_service_id $auth_token "chargeback"`
if [ "${OK}" != "" ]; then
    echo "Chargeback service already exists."
else
    create_service $auth_token chargeback chargeback "chargeback" RegionOne "http://localhost:8080/chargeback" "" "http://localhost:8080/chargeback"
    echo "Chargeback service created."
fi

SERVICE_TENANT_ID=`get_tenant_id $auth_token service`
if [ "${SERVICE_TENANT_ID}" != "" ]; then
    echo "'service' tenant exists. Everything is ok."
else
    echo "'service' tenant does not exists. There is something wrong in your OpenStack installation. Exiting."
    exit 1
fi

USER_CHARGEBACK_ID=`get_user_id $auth_token chargeback`
if [ "${USER_CHARGEBACK_ID}" != "" ]; then
    echo "'chargeback' already exists."
else
    USER_CHARGEBACK_ID=`create_user $auth_token chargeback $SERVICE_TENANT_ID $2`
    echo "'chargeback' user created."
fi

OK=`bind_user_role_tenant $auth_token $USER_CHARGEBACK_ID $ROLE_ADMIN $SERVICE_TENANT_ID`
