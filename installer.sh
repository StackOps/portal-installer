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
ScriptVersion="1.0"
ScriptName="installer.sh"

InstallPortal="false"
InstallChargeback="false"
InstallMySql="false"
InstallApache="false"
InstallApacheWithSSL="false"
PortalMySqlUsr="portal"
PortalMySqlPassword="stackops"
PortalMySqlSchema="portal"
ActivityMySqlUsr="activity"
ActivityMySqlPassword="stackops"
ActivityMySqlSchema="activity"
ChargebackMySqlUsr="chargeback"
ChargebackMySqlPassword="stackops"
ChargebackMySqlSchema="chargeback"
ChargebackKeystoneUsr="chargeback"
ChargebackKeystonePassword="stackops"
MySqlHost="localhost"
MySqlPort="3306"
KeystoneUrl="http://localhost:5000/v2.0"
MYSQL_ROOT_PASSWORD="stackops"
OS_USERNAME="admin"
OS_PASSWORD=""
OS_TENANT_NAME="admin"
OS_AUTH_URL="http://api.stackops.net:35357/v2.0"
OS_AUTH_TOKEN="stackops"
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USR=guest
RABBITMQ_PASSWORD=guest

KEYSTONE_CMD="keystone --os-auth-url $OS_AUTH_URL --os-username $OS_USERNAME --os-password $OS_PASSWORD --os-tenant-name $OS_TENANT_NAME --insecure"

usage() {
    cat << EOT

  Usage :  ${ScriptName} [options] <install-args>

  Options:
  -h|help       Display this message
  -v|version    Display script version
  -c|chargeback	Installs StackOps Chargeback
  -p|portal	Installs StackOps Portal
  -m|mysql	Installs MySQL server
  -a|apache	Installs Apache server for HTTP traffic
  -s|ssl	Installs Apache server for HTTPS traffic (SSL)
EOT
}

while getopts "hvcmasp" opt
do
  case $opt in

    h|help          )  usage; exit 0   ;;

    v|version       )  echo "$0 -- Version $ScriptVersion"; 
		       exit 0   ;;

    c|chargeback    )  echo "\nA StackOps Chargeback will be installed on this server\n"
                       InstallChargeback="true";  ;;

    m|mysql         )  echo "\nA MySQL server will be installed on this server\n"
                       InstallMySql="true";  ;;

    a|apache        )  echo "\nAn Apache server for HTTP traffic will be installed on this server\n"
                       InstallApache="true";  ;;

    s|ssl           )  echo "\nAn Apache server for HTTPS traffic will be installed on this server\n"
                       InstallApacheWithSSL="true";  ;;

    p|portal        )  echo "\nA StackOps Portal will be installed on this server\n"
                       InstallPortal="true";  ;;

    \?              )  echo "\n  Option does not exist : $OPTARG\n"
                       usage; exit 1   ;;
  esac
  echo $opt
done
shift $(($OPTIND-1))

__check_unparsed_options() {
    shellopts="$1"
    unparsed_options=$( echo "$shellopts" | grep -E '[-]+[[:alnum:]]' )
    if [ "x$unparsed_options" != "x" ]; then
        usage
        echo
        echo " * ERROR: options come before install arguments"
        echo
        exit 1
    fi
}

if [ "$#" -gt 5 ]; then
    __check_unparsed_options "$*"
    usage
    echo
    echo " * ERROR: Too many arguments."
    exit 1
fi

# Root permissions are required to run this script
if [ $(whoami) != "root" ] ; then
    echo " * ERROR: Requires root. Please re-run this script as root."
    exit 1
fi

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __gather_hardware_info
#   DESCRIPTION:  Discover hardware information
#-------------------------------------------------------------------------------
__gather_hardware_info() {
    if [ -f /proc/cpuinfo ]; then
        CPU_VENDOR_ID=$(cat /proc/cpuinfo | grep -E 'vendor_id|Processor' | head -n 1 | awk '{print $3}' | cut -d '-' -f1 )
    else
        CPU_VENDOR_ID=$( sysctl -n hw.model )
    fi
    CPU_VENDOR_ID_L=$( echo $CPU_VENDOR_ID | tr '[:upper:]' '[:lower:]' )
    CPU_ARCH=$(uname -m 2>/dev/null || uname -p 2>/dev/null || echo "unknown")
    CPU_ARCH_L=$( echo $CPU_ARCH | tr '[:upper:]' '[:lower:]' )

}
__gather_hardware_info


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __gather_os_info
#   DESCRIPTION:  Discover operating system information
#-------------------------------------------------------------------------------
__gather_os_info() {
    OS_NAME=$(uname -s 2>/dev/null)
    OS_NAME_L=$( echo $OS_NAME | tr '[:upper:]' '[:lower:]' )
    OS_VERSION=$(uname -r)
    OS_VERSION_L=$( echo $OS_VERSION | tr '[:upper:]' '[:lower:]' )
}
__gather_os_info


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __parse_version_string
#   DESCRIPTION:  Parse version strings ignoring the revision.
#                 MAJOR.MINOR.REVISION becomes MAJOR.MINOR
#-------------------------------------------------------------------------------
__parse_version_string() {
    VERSION_STRING="$1"
    PARSED_VERSION=$(
        echo $VERSION_STRING |
        sed -e 's/^/#/' \
            -e 's/^#[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\)\(\.[0-9][0-9]*\).*$/\1/' \
            -e 's/^#[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\).*$/\1/' \
            -e 's/^#[^0-9]*\([0-9][0-9]*\).*$/\1/' \
            -e 's/^#.*$//'
    )
    echo $PARSED_VERSION
}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __gather_linux_system_info
#   DESCRIPTION:  Discover Linux system information
#-------------------------------------------------------------------------------
__gather_linux_system_info() {
    DISTRO_NAME=""
    DISTRO_VERSION=""

    if [ -f /etc/lsb-release ]; then
        DISTRO_NAME=$(grep DISTRIB_ID /etc/lsb-release | sed -e 's/.*=//')
        DISTRO_VERSION=$(__parse_version_string $(grep DISTRIB_RELEASE /etc/lsb-release | sed -e 's/.*=//'))
    fi

    if [ "x$DISTRO_NAME" != "x" -a "x$DISTRO_VERSION" != "x" ]; then
        # We already have the distribution name and version
        return
    fi

    for rsource in $(
            cd /etc && /bin/ls *[_-]release *[_-]version 2>/dev/null | env -i sort | \
            sed -e '/^redhat-release$/d' -e '/^lsb-release$/d'; \
            echo redhat-release lsb-release
            ); do

        [ -L "/etc/${rsource}" ] && continue        # Don't follow symlinks
        [ ! -f "/etc/${rsource}" ] && continue      # Does not exist

        n=$(echo ${rsource} | sed -e 's/[_-]release$//' -e 's/[_-]version$//')
        v=$( __parse_version_string "$( (grep VERSION /etc/${rsource}; cat /etc/${rsource}) | grep '[0-9]' | sed -e 'q' )" )
        case $(echo ${n} | tr '[:upper:]' '[:lower:]') in
            redhat )
                if [ ".$(egrep '(Red Hat Enterprise Linux|CentOS)' /etc/${rsource})" != . ]; then
                    n="<R>ed <H>at <E>nterprise <L>inux"
                else
                    n="<R>ed <H>at <L>inux"
                fi
                ;;
            arch               ) n="Arch"           ;;
            centos             ) n="CentOS"         ;;
            debian             ) n="Debian"         ;;
            ubuntu             ) n="Ubuntu"         ;;
            fedora             ) n="Fedora"         ;;
            suse               ) n="SUSE"           ;;
            mandrake*|mandriva ) n="Mandriva"       ;;
            gentoo             ) n="Gentoo"         ;;
            slackware          ) n="Slackware"      ;;
            turbolinux         ) n="TurboLinux"     ;;
            unitedlinux        ) n="UnitedLinux"    ;;
            *                  ) n="${n}"           ;
        esac
        DISTRO_NAME=$n
        DISTRO_VERSION=$v
        break
    done
}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __gather_sunos_system_info
#   DESCRIPTION:  Discover SunOS system info
#-------------------------------------------------------------------------------
__gather_sunos_system_info() {
    DISTRO_NAME="Solaris"
    DISTRO_VERSION=$(
        echo "${OS_VERSION}" |
        sed -e 's;^4\.;1.;' \
            -e 's;^5\.\([0-6]\)[^0-9]*$;2.\1;' \
            -e 's;^5\.\([0-9][0-9]*\).*;\1;'
    )
}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __gather_bsd_system_info
#   DESCRIPTION:  Discover OpenBSD, NetBSD and FreeBSD systems information
#-------------------------------------------------------------------------------
__gather_bsd_system_info() {
    DISTRO_NAME=${OS_NAME}
    DISTRO_VERSION=$(echo "${OS_VERSION}" | sed -e 's;[()];;' -e 's/-.*$//')
}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __gather_system_info
#   DESCRIPTION:  Discover which system and distribution we are running.
#-------------------------------------------------------------------------------
__gather_system_info() {
    case ${OS_NAME_L} in
        linux )
            __gather_linux_system_info
            ;;
        sunos )
            __gather_sunos_system_info
            ;;
        openbsd|freebsd|netbsd|darwin )
            __gather_bsd_system_info
            ;;
        * )
            echo " * ERROR: $OS_NAME not supported.";
            exit 1
            ;;
    esac

}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __function_defined
#   DESCRIPTION:  Checks if a function is defined within this scripts scope
#    PARAMETERS:  function name
#       RETURNS:  0 or 1 as in defined or not defined
#-------------------------------------------------------------------------------
__function_defined() {
    FUNC_NAME=$1
    if [ "${DISTRO_NAME}" = "centos" ]; then
        if typeset -f $FUNC_NAME &>/dev/null ; then
            echo " * INFO: Found function $FUNC_NAME"
            return 0
        fi
    elif [ "${DISTRO_NAME}" = "ubuntu" ]; then
        if $( type ${FUNC_NAME} | grep -q 'shell function' ); then
            echo " * INFO: Found function $FUNC_NAME"
            return 0
        fi
    # Last resorts try POSIXLY_CORRECT or not
    elif test -n "${POSIXLY_CORRECT+yes}"; then
        if typeset -f $FUNC_NAME >/dev/null 2>&1 ; then
            echo " * INFO: Found function $FUNC_NAME"
            return 0
        fi
    else
        # Arch linux seems to fall here
        if $( type ${FUNC_NAME}  >/dev/null 2>&1 ) ; then
            echo " * INFO: Found function $FUNC_NAME"
            return 0
        fi
    fi
    echo " * INFO: $FUNC_NAME not found...."
    return 1
}
__gather_system_info

echo " * System Information:"
echo "     CPU:          ${CPU_VENDOR_ID}"
echo "     CPU Arch:     ${CPU_ARCH}"
echo "     OS Name:      ${OS_NAME}"
echo "     OS Version:   ${OS_VERSION}"
echo "     Distribution: ${DISTRO_NAME} ${DISTRO_VERSION}"


# Simplify version naming on functions
if [ "x${DISTRO_VERSION}" = "x" ]; then
    DISTRO_VERSION_NO_DOTS=""
else
    DISTRO_VERSION_NO_DOTS="_$(echo $DISTRO_VERSION | tr -d '.')"
fi
# Simplify distro name naming on functions
DISTRO_NAME_L=$(echo $DISTRO_NAME | tr '[:upper:]' '[:lower:]' | sed 's/[^a-zA-Z0-9_ ]//g' | sed -e 's|[:space:]+|_|g')

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  __apt_get_noinput
#   DESCRIPTION:  (DRY) apt-get install with noinput options
#-------------------------------------------------------------------------------
__apt_get_noinput() {
    DEBIAN_FRONTEND=noninteractive
    apt-get install -y -o DPkg::Options::=--force-confold $@
    DEBIAN_FRONTEND=
}

__apt_get_update() {
    apt-get update -y
}

__check_command() {
    command -v $1 >/dev/null 2>&1 || { echo >&2 "I require $1 but it's not installed.  Aborting."; exit 1; }
}

__get_auth_token() {
    credentials=`curl -s -d "{\"auth\":{\"passwordCredentials\": {\"username\": \"$OS_USERNAME\", \"password\": \"$OS_PASSWORD\"}, \"tenantName\": \"$OS_TENANT_NAME\"}}" -H "Content-type: application/json" $OS_AUTH_URL/tokens`
    auth_token=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['access']['token']['id'];"`
    [ ! -z "${auth_token}" ] || { echo >&2 `echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['error'];"`; exit 1; }
    echo $auth_token
}

__is_portal_admin() {
    credentials=`curl -s $OS_AUTH_URL/tokens/$1 -H "X-Auth-Token:$1" -H "Content-type: application/json"`
    set +e
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); t = tok['access']['user']['roles']; print any(d['name'] == 'ROLE_PORTAL_ADMIN' for d in t) "`
    set -e
    [ ! -z "${result}" ] || { echo >&2 `echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['error'];"`; }
    echo $result
}

__is_chargeback_roles() {
    credentials=`curl -s $OS_AUTH_URL/tokens/$1 -H "X-Auth-Token:$1" -H "Content-type: application/json"`
    set +e
    result_activity=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); t = tok['access']['user']['roles']; print any(d['name'] == 'ROLE_ACTIVITY' for d in t) "`
    result_accounting=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); t = tok['access']['user']['roles']; print any(d['name'] == 'ROLE_ACCOUNTING' for d in t) "`
    result_chargeback=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); t = tok['access']['user']['roles']; print any(d['name'] == 'ROLE_CHARGEBACK' for d in t) "`
    result_activity_admin=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); t = tok['access']['user']['roles']; print any(d['name'] == 'ROLE_ACTIVITY_ADMIN' for d in t) "`
    result_chargeback_admin=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); t = tok['access']['user']['roles']; print any(d['name'] == 'ROLE_CHARGEBACK_ADMIN' for d in t) "`
    set -e
    result="True"
    if [ "${result_activity}" = "False" ]; then
        result="ROLE_ACTIVITY does not exist.\n"
    fi
    if [ "${result_activity_admin}" = "False" ]; then
        result="ROLE_ACTIVITY_ADMIN does not exist.\n"
    fi
    if [ "${result_accounting}" = "False" ]; then
        result="ROLE_ACCOUNTING does not exist.\n"
    fi
    if [ "${result_chargeback}" = "False" ]; then
        result="ROLE_CHARGEBACK does not exist.\n"
    fi
    if [ "${result_chargeback_admin}" = "False" ]; then
        result="ROLE_CHARGEBACK_ADMIN does not exist.\n"
    fi
    echo $result
}

__configure_apt_repos() {
    echo "deb http://repos.stackops.net/ $1 main" > /etc/apt/sources.list.d/stackops.list
    wget -O - http://repos.stackops.net/keys/stackopskey_pub.gpg | apt-key add -
    __apt_get_update
}

__configure_clinker_key() {
    wget $1
    set +e
    keytool -keystore /usr/lib/jvm/java-7-openjdk-amd64/jre/lib/security/cacerts -delete -alias clinker -storepass changeit  -noprompt
    set -e
    keytool -keystore /usr/lib/jvm/java-7-openjdk-amd64/jre/lib/security/cacerts -storepass changeit -import -trustcacerts -v -alias clinker -file clinker.cert -noprompt
    rm clinker.cert
}

__configure_apache() {
    a2enmod proxy_http
    a2enmod rewrite
    rm /etc/apache2/sites-enabled/* 
    rename 's/(.*)/$1.bak/' /etc/apache2/sites-available/* 
cat <<EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName  localhost
    ProxyPreserveHost On
    ProxyRequests Off
    ProxyPass /portal http://127.0.0.1:8080/portal
    ProxyPassReverse /portal http://127.0.0.1:8080/portal
    RewriteEngine on
    RewriteRule ^/$ http://%{HTTP_HOST}/portal [R]
    <Proxy *>
        Order allow,deny
        Allow from all
    </Proxy>
    ErrorLog /var/log/apache2/apache-portal-error.log
    TransferLog /var/log/apache2/apache-portal-access.log
</VirtualHost>
EOF
    ln -s /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-enabled/000-default.conf
}

__configure_apache_ssl() {
    a2enmod proxy_http
    a2enmod ssl
    a2enmod rewrite
    a2ensite default-ssl
    rm /etc/apache2/sites-enabled/* 
    rename 's/(.*)/$1.bak/' /etc/apache2/sites-available/*
cat <<EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName  localhost
    ProxyPreserveHost On
    ProxyRequests Off
    ProxyPass /portal http://127.0.0.1:8080/portal
    ProxyPassReverse /portal http://127.0.0.1:8080/portal
    RewriteEngine on
    RewriteRule ^/$ https://%{HTTP_HOST}/portal [R]
    ReWriteCond %{SERVER_PORT} !^443\$
    RewriteRule ^/(.*) https://%{HTTP_HOST}/\$1 [NC,R,L]
    <Proxy *>
        Order allow,deny
        Allow from all
    </Proxy>
    ErrorLog /var/log/apache2/apache-portal-error.log
    TransferLog /var/log/apache2/apache-portal-access.log
</VirtualHost>
EOF
    ln -s /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-enabled/000-default.conf

cat <<EOF > /etc/apache2/sites-available/000-default-ssl.conf
<IfModule mod_ssl.c>
<VirtualHost *:443>
   ServerAdmin webmaster@localhost
   ServerName  localhost
   ProxyPreserveHost On
   ProxyRequests Off
   ProxyPass /portal http://127.0.0.1:8080/portal
   ProxyPassReverse /portal http://127.0.0.1:8080/portal
   <Proxy *>
       Order allow,deny
       Allow from all
   </Proxy>
   ErrorLog /var/log/apache2/apachessl-portal-error.log
   TransferLog /var/log/apache2/apachessl-portal-access.log
   SSLEngine on
   RewriteEngine on
   RewriteRule ^/$ https://%{HTTP_HOST}/portal [R]
   SSLCertificateFile /etc/ssl/certs/sslcert.crt
   SSLCertificateKeyFile /etc/ssl/private/sslcert.key
   <FilesMatch "\.(cgi|shtml|phtml|php)$">
       SSLOptions +StdEnvVars
   </FilesMatch>
   <Directory /usr/lib/cgi-bin>
       SSLOptions +StdEnvVars
   </Directory>
   BrowserMatch "MSIE [2-6]" nokeepalive ssl-unclean-shutdown downgrade-1.0 force-response-1.0
   # MSIE 7 and newer should be able to use keepalive
   BrowserMatch "MSIE [17-9]" ssl-unclean-shutdown
</VirtualHost>
</IfModule>
EOF
    ln -s /etc/apache2/sites-available/000-default-ssl.conf /etc/apache2/sites-enabled/000-default-ssl.conf

cat <<EOF > /tmp/nonsecure.key
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtO4zZwNYOzux+ymvrW7kMojJ9diI7WxmPvESa1FNdY45TN5Z
WYSYcgYKDT/OuHDi9+49LlRPksV35scGNIJbqV9Cr4L0vHXfb9E9EdOIIkv3jOG9
QhhwIPxKrpJQP1hkPyxybWkH/IVHY06OxLIWPJO3NC74sQQvXZ2mMUoOW5KcQwiK
GfWf3mJKCccocNv3MXP4cb6ay7DQtbgQigjZaoQxffkJvq083h3y5lSQpnI56yBE
XHtHam8XCPnu7Axj0v5AGGaTYOa4RAzkG8PKpcvL8TRjPL3TMiiKJM2rQVrHdjcK
qBSOCr+fSNlr7E5KVBN8pfrsmly+NoflhA7hdQIDAQABAoIBAQCyz2rrlsmfGJsI
TyV48MwECV4XYt3IT0YpVFTQzPQRhvKoPmLtbna+0asjdvkVHTOitcevPtG5iwC5
id5fDKoMFMIx9OlsS837kz2YnYa/5nYLvJkvdjly0AP6zU0TnYbNTF72NEQZU5q+
0UeVqy8AxTfdEcLkJu+sxH4X3kmcQvhz2q7L2pbSgZ0JeL1Nfxmy0cjsSKEVy3qY
0tLVm4xHStoYNBpzgXyBqhz/wAhOcctUyl5qvpNzgR+ihASNRKYKIGcpjgjaSryk
0Gp8WmwrSuy1qQ8iqKRkSa5SSWqwl1umWlb1V8+7m4ic0A/GJEhzJ5pfXPMaOQuF
eHG60JNNAoGBAOyA1R1US5mjoaIZmahR2Rl6nYFQQy3HNqQy1AZU5hB4uTrMA2eW
sSxt1RMBjlE9C0sUOFB95w48/gZNI6JPdMFGgcux5WrndDruY8txiVl3rw2Dw7Ih
JMxNBsJRO0AZgijUm11HPBp/tJ4HjppZiqE0exjoNFGOLc/l4VOZ1PbDAoGBAMPY
j0dS7eHcsmu+v6EpxbRFwSyZG0eV51IiT0DFLfiSpsfmtHdA1ZQeqbVadM1WJSLu
ZJ8uvGNRnuLgz2vwKdI6kJFfWYZSS5jfnl874/OF6riNQDseX5CvB5zQvTFVmae+
Mld4x2NYFxQ1vIWnGITGQKhcZonBMyAjaQ9tAnNnAoGASvTOFpyX1VryKHEarSk7
uIKPFuP8Vq7z13iwkE0qGYBZnJP6ZENzZdRtmrd8hqzlPmdrLb+pkm6sSAz8xT2P
kI4rJwb74jT3NpJFmL4kPPHczli7lmJAymuDP+UE9VzgTtaLYzXni7J76TYV8T99
23fJp+w4YLzCMkj2cEuqHocCgYBb2KEBMwwqw4TNcOyP2XZFn/0DPF6FyPBuHXcL
ii2QCL68ux5hWv+O8n5mdaCXd9H8us5ntNRWw71+6y17kmsak6qe8peandekPyMX
yI+T8nbszBmWYB0zTlKEoYRIsbtY5qLXUOY5WeOg776U85NVGWDTVFomOnwOk2y+
9kGS+wKBgD3cL/zabIv/kK7KY84EdWdVH4sal3bRsiNn4ezj7go/ObMgR59O4Lr4
fYqT1igILotduz/knlkleY2fsqltStWYzRrG+/zNryIBco2+cIX8T120AnpbAvlP
gj0YVjuLJXSC9w/URFG+ZGg0kX0Koy1yS6fuxikiA4f5Lw9znjaD
-----END RSA PRIVATE KEY-----
EOF

openssl req -nodes -newkey rsa:2048 -keyout /tmp/nonsecure.key -out /tmp/server.csr -subj "/C=ES/ST=MADRID/L=MADRID/O=STACKOPS TECHNOLOGIES SL./OU=STACKOPS PORTAL/CN=127.0.0.1"
openssl rsa -in /tmp/nonsecure.key -out /tmp/ssl.key
openssl x509 -req -days 365 -in /tmp/server.csr -signkey /tmp/ssl.key -out /tmp/ssl.crt
cp /tmp/ssl.crt /etc/ssl/certs/sslcert.crt
cp /tmp/ssl.key /etc/ssl/private/sslcert.key
}

# Create role
__create_role()
{
    echo "`$KEYSTONE_CMD role-create --name=$1 | grep id | awk '/ | / { print $4 }' | head -n 1`"
}

# Get the role Id
__get_role_id()
{
    echo "`$KEYSTONE_CMD role-list | grep $1 | awk '/ | / { print $2 }' | head -n 1`"
}

# Create role
__create_user()
{
    echo "`$KEYSTONE_CMD user-create --name $1 --tenant $2 --pass $3 --enabled true | grep id | awk '/ | / { print $4 }' | head -n 1`"
}

# Get the user Id
__get_user_id()
{
    echo "`$KEYSTONE_CMD user-list | grep $1 | awk '/ | / { print $2 }' | head -n 1`"
}

# Bind user to role with tenant
__bind_user_role_tenant()
{
    echo "`$KEYSTONE_CMD user-role-add --user-id $1 --role-id $2 --tenant-id $3`"
}

__create_service()
{
    service_id=`$KEYSTONE_CMD service-create --name=$1 --type=$2 --description="$3" | awk '/ id / { print $4 }' `
    $KEYSTONE_CMD endpoint-create --region $4 --service-id $service_id --publicurl "$5" --adminurl "$6" --internalurl "$7"
}

__get_service_id()
{
   echo "`$KEYSTONE_CMD service-get $1 | grep id | awk '/ id / { print $4 }' `"
}

# Get the tenant Id
__get_tenant_id()
{
    echo "`$KEYSTONE_CMD tenant-list | grep "$1" | awk '/ | / { print $2 }' | head -n 1`"
}

__configure_portal_keystone() {

ROLE_PORTAL_ADMIN=`__get_role_id ROLE_PORTAL_ADMIN`
ROLE_PORTAL_USER=`__get_role_id ROLE_PORTAL_USER`

USER_ADMIN_ID=`__get_user_id admin`
ADMIN_TENANT_ID=`__get_tenant_id admin`

if [ ! -z "${ROLE_PORTAL_ADMIN}" ]; then
    echo "ROLE_PORTAL_ADMIN ID: $ROLE_PORTAL_ADMIN"
else
    echo "ROLE_PORTAL_ADMIN role does not exists. Creating."
    ROLE_PORTAL_ADMIN=`__create_role ROLE_PORTAL_ADMIN`
    echo "ROLE_PORTAL_ADMIN ID: $ROLE_PORTAL_ADMIN"
fi

if [ ! -z "${ROLE_PORTAL_USER}" ]; then
    echo "ROLE_PORTAL_USER ID: $ROLE_PORTAL_USER"
else
    echo "ROLE_PORTAL_USER role does not exists. Creating."
    ROLE_PORTAL_USER=`__create_role ROLE_PORTAL_USER`
    echo "ROLE_PORTAL_USER ID: $ROLE_PORTAL_USER"
fi

OK=`__bind_user_role_tenant $USER_ADMIN_ID $ROLE_PORTAL_ADMIN $ADMIN_TENANT_ID`
OK=`__bind_user_role_tenant $USER_ADMIN_ID $ROLE_PORTAL_USER $ADMIN_TENANT_ID`

}

__configure_chargeback_keystone() {

ROLE_ADMIN=`__get_role_id admin`
ROLE_ACCOUNTING=`__get_role_id ROLE_ACCOUNTING`
ROLE_ACTIVITY=`__get_role_id ROLE_ACTIVITY`
ROLE_ACTIVITY_ADMIN=`__get_role_id ROLE_ACTIVITY_ADMIN`
ROLE_CHARGEBACK=`__get_role_id ROLE_CHARGEBACK`
ROLE_CHARGEBACK_ADMIN=`__get_role_id ROLE_CHARGEBACK_ADMIN`

USER_ADMIN_ID=`__get_user_id admin`
ADMIN_TENANT_ID=`__get_tenant_id admin`

if [ ! -z "${ROLE_ADMIN}" ]; then
    echo "ROLE_ADMIN_ID: $ROLE_ADMIN"
else
    echo "admin role does not exists. There is something wrong in your OpenStack installation."
    exit  1
fi

if [ ! -z "${ROLE_ACCOUNTING}" ]; then
    echo "ROLE_ACCOUNTING ID: $ROLE_ACCOUNTING"
else
       echo "ROLE_ACCOUNTING role does not exists. Creating."
    ROLE_ACCOUNTING=`__create_role ROLE_ACCOUNTING`
    echo "ROLE_ACCOUNTING ID: $ROLE_ACCOUNTING"
fi

if [ ! -z "${ROLE_ACTIVITY}" ]; then
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY"
    echo "ROLE_ACTIVITY role does not exists. Creating."
else
    ROLE_ACTIVITY=`__create_role ROLE_ACTIVITY`
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY"
fi

if [ ! -z "${ROLE_ACTIVITY_ADMIN}" ]; then
    echo "ROLE_ACTIVITY ID: $ROLE_ACTIVITY_ADMIN"
else
    echo "ROLE_ACTIVITY_ADMIN role does not exists. Creating."
    ROLE_ACTIVITY_ADMIN=`__create_role ROLE_ACTIVITY_ADMIN`
    echo "ROLE_ACTIVITY_ADMIN ID: $ROLE_ACTIVITY_ADMIN"
fi

if [ ! -z "${ROLE_CHARGEBACK}" ]; then
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK"
else
    echo "ROLE_CHARGEBACK role does not exists. Creating."
    ROLE_CHARGEBACK=`__create_role ROLE_CHARGEBACK`
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK"
fi

if [ ! -z "${ROLE_CHARGEBACK_ADMIN}" ]; then
    echo "ROLE_CHARGEBACK ID: $ROLE_CHARGEBACK_ADMIN"
else
    echo "ROLE_CHARGEBACK_ADMIN role does not exists. Creating."
    ROLE_CHARGEBACK_ADMIN=`__create_role ROLE_CHARGEBACK_ADMIN`
    echo "ROLE_CHARGEBACK_ADMIN ID: $ROLE_CHARGEBACK_ADMIN"
fi

OK=`__bind_user_role_tenant $USER_ADMIN_ID $ROLE_ACCOUNTING $ADMIN_TENANT_ID`
OK=`__bind_user_role_tenant $USER_ADMIN_ID $ROLE_ACTIVITY $ADMIN_TENANT_ID`
OK=`__bind_user_role_tenant $USER_ADMIN_ID $ROLE_ACTIVITY_ADMIN $ADMIN_TENANT_ID`
OK=`__bind_user_role_tenant $USER_ADMIN_ID $ROLE_CHARGEBACK $ADMIN_TENANT_ID`
OK=`__bind_user_role_tenant $USER_ADMIN_ID $ROLE_CHARGEBACK_ADMIN $ADMIN_TENANT_ID`

OK=`__get_service_id "activity"`
if [ "${OK}" != "" ]; then
    echo "Activity service already exists."
else
    __create_service activity activity "activity" RegionOne "http://localhost:8080/activity" "" "http://localhost:8080/activity"
    echo "Activity service created."
fi

OK=`get_service_id "accounting"`
if [ "${OK}" != "" ]; then
    echo "Accounting service already exists."
else
    __create_service accounting accounting "accounting" RegionOne "http://localhost:8080/activity" "" "http://localhost:8080/activity"
    echo "Accounting service created."
fi

OK=`get_service_id "chargeback"`
if [ "${OK}" != "" ]; then
    echo "Chargeback service already exists."
else
    __create_service chargeback chargeback "chargeback" RegionOne "http://localhost:8080/chargeback" "" "http://localhost:8080/chargeback"
    echo "Chargeback service created."
fi

SERVICE_TENANT_ID=`__get_tenant_id service`
if [ "${SERVICE_TENANT_ID}" != "" ]; then
    echo "'service' tenant exists. Everything is ok."
else
    echo "'service' tenant does not exists. There is something wrong in your OpenStack installation. Exiting."
    exit 1
fi

USER_CHARGEBACK_ID=`__get_user_id chargeback`
if [ "${USER_CHARGEBACK_ID}" != "" ]; then
    echo "'chargeback' already exists."
else
    USER_CHARGEBACK_ID=`__create_user chargeback service $ChargebackKeystonePassword`
    echo "'chargeback' user created."
fi

OK=`__bind_user_role_tenant $USER_CHARGEBACK_ID $ROLE_ADMIN $SERVICE_TENANT_ID`

}


__check_keystone(){


echo "GLOBAL OPENSTACK PARAMETERS"
echo "==========================="
echo "All StackOps componentes follows the design guidelines of an OpenStack architecture. Please enter below the Public and Admin Authentication URLs of your OpenStack platform. You also need to provide the Authentication Admin token. The installer also needs an admin user with credentials to check the correct configuration of the roles for our components."

exitloop="none"
while [ "$exitloop" == "none" ]
do
    echo "Enter the authentication admin url [$OS_AUTH_URL]: "
    read response
    if [ -n "$response" ]; then
        OS_AUTH_URL=$response
    fi

    echo "Enter the authentication url [${KeystoneUrl}]: "
    read response
    if [ -n "$response" ]; then
        KeystoneUrl=$response
    fi

    echo "Enter the authentication admin token [$OS_AUTH_TOKEN]: "
    read response
    if [ -n "$response" ]; then
        OS_AUTH_TOKEN=$response
    fi

    echo "Enter the username with admin privileges [$OS_USERNAME]: "
    read response
    if [ -n "$response" ]; then
        OS_USERNAME=$response
    fi

    echo "Enter the tenant [$OS_TENANT_NAME]: "
    read response
    if [ -n "$response" ]; then
        OS_TENANT_NAME=$response
    fi
    exitloop="exit"
done

exitloop="none"
while [ "$exitloop" == "none" ]
do
    echo "Enter the password: "
    read response
    if [ -n "$response" ]; then
        OS_PASSWORD=$response
        exitloop="exit"
    fi
done

echo "GLOBAL MYSQL PARAMETERS"
echo "======================="
echo "The StackOps componentes use MySQL as the default persistent database.  You need to provide the root password of your database installation, no matter if you are using an existing database server. If you are using an existing database server the installer will ask for the host and port."
if [ "${InstallMySql}" != "true" ]; then
    echo "Enter the MySQL Host [${MySqlHost}]: "
    read response
    if [ -n "$response" ]; then
        MySqlHost=$response
    fi

    echo "Enter the MySQL Port [${MySqlPort}]: "
    read response
    if [ -n "$response" ]; then
        MySqlPort=$response
    fi
fi

echo "Enter the MySQL ROOT password [$MYSQL_ROOT_PASSWORD]: "
read response
if [ -n "$response" ]; then
    MYSQL_ROOT_PASSWORD=$response
fi

echo "STACKOPS PORTAL PARAMETERS"
echo "=========================="
echo "StackOps Portal needs the username, password and the name of the schema. Please enter the information below:"
if [ "${InstallPortal}" = "true" ]; then
   echo "Enter the Portal MySQL user [${PortalMySqlUsr}]: "
   read response
   if [ -n "$response" ]; then
        PortalMySqlUsr=$response
    fi

    echo "Enter the Portal MySQL password [${PortalMySqlPassword}]: "
    read response
    if [ -n "$response" ]; then
        PortalMySqlPassword=$response
    fi

    echo "Enter the Portal MySQL Database Schema [${PortalMySqlSchema}]: "
    read response
    if [ -n "$response" ]; then
        PortalMySqlSchema=$response
    fi
fi

echo "STACKOPS CHARGEBACK PARAMETERS"
echo "=========================="
echo "StackOps Chargeback needs an schema for data logging and another for rating processing. The install will ask for both username, password and the name of the schema. The installer will ask for the AQMP host and port plus the username and password. Finally, you need to enter the username and password of the account created for the component in keystone. Please enter the information below:"
if [ "${InstallChargeback}" = "true" ]; then
    echo "Enter the Activity MySQL user [${ActivityMySqlUsr}]: "
    read response
    if [ -n "$response" ]; then
        ActivityMySqlUsr=$response
    fi

    echo "Enter the Activity MySQL password [${ActivityMySqlPassword}]: "
    read response
    if [ -n "$response" ]; then
        ActivityMySqlPassword=$response
    fi

    echo "Enter the Activity MySQL Database Schema [${ActivityMySqlSchema}]: "
    read response
    if [ -n "$response" ]; then
        ActivityMySqlSchema=$response
    fi

    echo "Enter the Chargeback MySQL user [${ChargebackMySqlUsr}]: "
    read response
    if [ -n "$response" ]; then
        ChargebackMySqlUsr=$response
    fi

    echo "Enter the Chargeback MySQL password [${ChargebackMySqlPassword}]: "
    read response
    if [ -n "$response" ]; then
        ChargebackMySqlPassword=$response
    fi

    echo "Enter the Chargeback MySQL Database Schema [${ChargebackMySqlSchema}]: "
    read response
    if [ -n "$response" ]; then
        ChargebackMySqlSchema=$response
    fi

    echo "Enter the Chargeback Keystone user [${ChargebackKeystoneUsr}]: "
    read response
    if [ -n "$response" ]; then
        ChargebacKeystoneUsr=$response
    fi

    echo "Enter the Chargeback Keystone password [${ChargebackKeystonePassword}]: "
    read response
    if [ -n "$response" ]; then
        ChargebackKeystonePassword=$response
    fi

    echo "Enter the AQMP Host [${RABBITMQ_HOST}]: "
    read response
    if [ -n "$response" ]; then
        RABBITMQ_HOST=$response
    fi

    echo "Enter the AQMP Port [${RABBITMQ_PORT}]: "
    read response
    if [ -n "$response" ]; then
        RABBITMQ_PORT=$response
    fi

    echo "Enter the AQMP username [$RABBITMQ_USR]: "
    read response
    if [ -n "$response" ]; then
        RABBITMQ_USR=$response
    fi

    echo "Enter the AQMP password [$RABBITMQ_PASSWORD]: "
    read response
    if [ -n "$response" ]; then
        RABBITMQ_PASSWORD=$response
    fi
fi

auth_token=`__get_auth_token`
#is_portal_admin=`__is_portal_admin $auth_token`
#is_chargeback_roles=`__is_chargeback_roles $auth_token`

KEYSTONE_CMD="keystone --os-auth-url $OS_AUTH_URL --os-username $OS_USERNAME --os-password $OS_PASSWORD --os-tenant-name $OS_TENANT_NAME --insecure"

if [ "${InstallPortal}" = "true" ]; then
    __configure_portal_keystone
fi

if [ "${InstallChargeback}" = "true" ]; then
    __configure_chargeback_keystone
fi

#echo $OS_USERNAME
#echo $OS_PASSWORD
#echo $OS_TENANT_NAME
#echo $OS_AUTH_URL
#echo $auth_token
#echo $is_portal_admin

}
__check_keystone

install_ubuntu_1404() {
    __configure_apt_repos "havana-dev"
    __check_command "curl"
    if [ "${InstallMySql}" = "true" ]; then
	echo "* Installing MySQL server...\n"
        echo mysql-server mysql-server/root_password password $MYSQL_ROOT_PASSWORD | debconf-set-selections
        echo mysql-server mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD | debconf-set-selections
        echo mysql-server mysql-server/start_on_boot boolean true | debconf-set-selections
        __apt_get_noinput mysql-server
    fi
    if [ "${InstallApache}" = "true" ]; then
	echo "* Installing Apache server without SSL...\n"
        __apt_get_noinput apache2
	__configure_apache
	service apache2 restart
    fi
    if [ "${InstallApacheWithSSL}" = "true" ]; then
	echo "* Installing Apache server with SSL...\n"
        __apt_get_noinput apache2
        __configure_apache_ssl
        service apache2 restart
    fi

    if [ "${InstallPortal}" = "true" ] || [ "${InstallChargeback}" = "true" ]; then
 	echo "* Installing OpenJDK and Tomcat...\n"
       __apt_get_noinput mysql-client
        __apt_get_noinput openjdk-7-jdk
        __configure_clinker_key http://static.stackops.net/clinker.cert
        __apt_get_noinput tomcat7
    fi

    if [ "${InstallPortal}" = "true" ]; then
	echo "* Installing StackOps Portal...\n"
	echo stackops-portal stackops-portal/present-stackops-license boolean true | debconf-set-selections
	echo stackops-portal stackops-portal/mysql-usr string ${PortalMySqlUsr} | debconf-set-selections
	echo stackops-portal stackops-portal/mysql-password password ${PortalMySqlPassword} | debconf-set-selections
	echo stackops-portal stackops-portal/mysql-schema string ${PortalMySqlSchema} | debconf-set-selections
	echo stackops-portal stackops-portal/mysql-host string ${MySqlHost} | debconf-set-selections
	echo stackops-portal stackops-portal/mysql-port string ${MySqlPort} | debconf-set-selections
	echo stackops-portal stackops-portal/mysql-admin-password password ${MYSQL_ROOT_PASSWORD} | debconf-set-selections
	echo stackops-portal stackops-portal/mysql-install boolean true | debconf-set-selections
        echo stackops-portal stackops-portal/mysql-purgedb boolean false | debconf-set-selections
	echo stackops-portal stackops-portal/keystone-url string ${KeystoneUrl} | debconf-set-selections
	echo stackops-portal stackops-portal/keystone-admin-url string ${OS_AUTH_URL} | debconf-set-selections
	echo stackops-portal stackops-portal/keystone-admin-token password ${OS_AUTH_TOKEN} | debconf-set-selections
        __apt_get_noinput stackops-portal
    fi

    if [ "${InstallChargeback}" = "true" ]; then
	echo "* Installing StackOps Chargeback...\n"
        echo stackops-activity stackops-activity/present-stackops-license boolean true | debconf-set-selections
        echo stackops-activity stackops-activity/mysql-usr string ${ActivityMySqlUsr} | debconf-set-selections
        echo stackops-activity stackops-activity/mysql-password password ${ActivityMySqlPassword} | debconf-set-selections
        echo stackops-activity stackops-activity/mysql-schema string ${ActivityMySqlSchema} | debconf-set-selections
        echo stackops-activity stackops-activity/mysql-host string ${MySqlHost} | debconf-set-selections
        echo stackops-activity stackops-activity/mysql-port string ${MySqlPort} | debconf-set-selections
        echo stackops-activity stackops-activity/mysql-admin-password password ${MYSQL_ROOT_PASSWORD} | debconf-set-selections
        echo stackops-activity stackops-activity/mysql-install boolean true | debconf-set-selections
        echo stackops-activity stackops-activity/mysql-purgedb boolean false | debconf-set-selections
        echo stackops-activity stackops-activity/keystone-url string ${OS_AUTH_URL} | debconf-set-selections
        echo stackops-activity stackops-activity/keystone-admin-token password ${OS_AUTH_TOKEN} | debconf-set-selections
        echo stackops-activity stackops-activity/keystone-usr string ${ChargebackKeystoneUsr} | debconf-set-selections
        echo stackops-activity stackops-activity/keystone-password password ${ChargebackKeystonePassword} | debconf-set-selections
        echo stackops-activity stackops-activity/rabbit-usr string ${RABBITMQ_USR} | debconf-set-selections
        echo stackops-activity stackops-activity/rabbit-password password ${RABBITMQ_PASSWORD} | debconf-set-selections
        echo stackops-activity stackops-activity/rabbit-host string ${RABBITMQ_HOST} | debconf-set-selections
        echo stackops-activity stackops-activity/rabbit-port string ${RABBITMQ_PORT} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/present-stackops-license boolean true | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-usr string ${ChargebackMySqlUsr} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-password password ${ChargebackMySqlPassword} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-schema string ${ChargebackMySqlSchema} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-activity-schema string ${ActivityMySqlSchema} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-host string ${MySqlHost} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-port string ${MySqlPort} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-admin-password password ${MYSQL_ROOT_PASSWORD} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-install boolean true | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/mysql-purgedb boolean false | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/keystone-url string ${OS_AUTH_URL} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/keystone-admin-token password ${OS_AUTH_TOKEN} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/keystone-usr string ${ChargebackKeystoneUsr} | debconf-set-selections
        echo stackops-chargeback stackops-chargeback/keystone-password password ${ChargebackKeystonePassword} | debconf-set-selections
        __apt_get_noinput stackops-activity
        __apt_get_noinput stackops-chargeback
    fi

    if [ "${InstallPortal}" = "true" ] || [ "${InstallChargeback}" = "true" ]; then
        service tomcat7 restart
    fi

}

post_install_ubuntu_1404() {
     echo "Post install on ubuntu_1404"
}

conf_ubuntu_1404() {
#    auth_token=`__get_auth_token`
#    echo "Token: $auth_token"
    echo "configuring the portal server"
}


install_ubuntu_1204() {
     install_ubuntu_1404
}

post_install_ubuntu_1204() {
     post_install_ubuntu_1404
}

conf_ubuntu_1204() {
    conf_ubuntu_1404
}

install_debian() {
     install_ubuntu_1404
}

post_install_debian() {
     post_install_ubuntu_1404
}

conf_debian() {
    conf_ubuntu_1404
}

DEPS_INSTALL_FUNC="install_${DISTRO_NAME_L}${DISTRO_VERSION_NO_DOTS}"
CONFIG_FUNC="conf_${DISTRO_NAME_L}${DISTRO_VERSION_NO_DOTS}"
POST_INSTALL_FUNC="post_install_${DISTRO_NAME_L}${DISTRO_VERSION_NO_DOTS}"

# Install dependencies
echo " * Running ${DEPS_INSTALL_FUNC}()"
$DEPS_INSTALL_FUNC
if [ $? -ne 0 ]; then
    echo " * Failed to run ${DEPS_INSTALL_FUNC}()!!!"
    exit 1
fi

# Configure basic stuff
$CONFIG_FUNC
if [ $? -ne 0 ]; then
    echo " * Failed to run ${CONFIG_FUNC}()!!!"
    exit 1
fi

if [ "$POST_INSTALL_FUNC" != "null" ]; then
    echo " * Running ${POST_INSTALL_FUNC}()"
    $POST_INSTALL_FUNC
    if [ $? -ne 0 ]; then
        echo " * Failed to run ${POST_INSTALL_FUNC}()!!!"
        exit 1
    fi
fi

# Done!
exit 0



