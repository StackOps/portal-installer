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

InstallMySql="false"
InstallApache="false"
InstallApacheWithSSL="false"
MYSQL_ROOT_PASSWORD="stackops"
OS_USERNAME="admin"
OS_PASSWORD=""
OS_TENANT_NAME="admin"
OS_AUTH_URL="http://api.stackops.net:35357/v2.0"

usage() {
    cat << EOT

  Usage :  ${ScriptName} [options] <install-args>

  Options:
  -h|help       Display this message
  -v|version    Display script version
  -m|mysql	Installs MySQL server
  -a|apache	Installs Apache server for HTTP traffic
  -s|ssl	Installs Apache server for HTTPS traffic (SSL)
EOT
}

while getopts ":hvmasc:" opt
do
  case $opt in

    h|help          )  usage; exit 0   ;;

    v|version       )  echo "$0 -- Version $ScriptVersion"; exit 0   ;;

    m|mysql         )  echo "\n * A MySQL server will be installed on this server\n"
                       InstallMySql="true";  ;;

    a|apache        )  echo "\n * An Apache server for HTTP traffic will be installed on this server\n"
                       InstallApache="true";  ;;

    s|ssl           )  echo "\n * An Apache server for HTTPS traffic will be installed on this server\n"
                       InstallApacheWithSSL="true";  ;;

    \?              )  echo "\n  Option does not exist : $OPTARG\n"
                       usage; exit 1   ;;

  esac
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
    apt-get install -y -o DPkg::Options::=--force-confold $@
}

__apt_get_update() {
    apt-get update -y
}

__check_command() {
    command -v $1 >/dev/null 2>&1 || { echo >&2 "I require $1 but it's not installed.  Aborting."; exit 1; }
}

__get_auth_token() {
    set +e
    credentials=`curl -s -d "{\"auth\":{\"passwordCredentials\": {\"username\": \"$OS_USERNAME\", \"password\": \"$OS_PASSWORD\"}, \"tenantName\": \"$OS_TENANT_NAME\"}}" -H "Content-type: application/json" $OS_AUTH_URL/tokens`
    auth_token=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['access']['token']['id'];"`
    [ ! -z "${auth_token}" ] || { echo >&2 `echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['error'];"`; }
    set -e
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

__is_keystone_admin() {
    set +e
    credentials=`curl -s $OS_AUTH_URL -H \"Content-type: application/json\"`
    result=`echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['version']['id']=='v2.0'"`
    [ ! -z "${result}" ] || { echo >&2 `echo $credentials | python -c "import sys; import json; tok = json.loads(sys.stdin.read()); print tok['error'];"`; }
    set -e
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

__show_instructions(){
    echo "\n\nWelcome to StackOps Portal assisted installer. This script will guide you through the installation process of StackOps Portal. Before proceeding, let's review the system requirements first:"
    echo "1) StackOps Portal needs to have access to Keystone Administration endpoint and also needs Keystone token."
    echo "2) The default installation also needs to have access to all OpenStack and StackOps APIs through the INTERNAL URL. This is mandatory."
    echo "3) To setup and configure the platform properly, an user with Administrator privileges is needed"
    echo "4) A special role must be created in your OpenStack Platform: ROLE_PORTAL_ADMIN"
    echo "5) Add this role to your user with Administrator privileges before continuing"
    echo "6) StackOps Portal needs a MySQL/MariaDB at runtime. You can install a dedicated database or use an external one."
    echo "7) You can optionally install an Apache server to proxy all traffic from port 80 or 443 to port 8080 (Tomcat). It's highly recommended for production environments".
    echo ""
    echo "And now, please enter the information to access Keystone before proceeding. The script will stop if some of the requirements are not fullfilled."
    echo ""
}

__show_instructions

__check_keystone(){
exitloop=0
while [ $exitloop -eq 0 ];
do
    echo -n "Enter the authentication admin url [$OS_AUTH_URL]: "
    read response
    if [ -n "$response" ]; then
        OS_AUTH_URL=$response
    fi

    echo -n "Enter the username with admin privileges [$OS_USERNAME]: "
    read response
    if [ -n "$response" ]; then
        OS_USERNAME=$response
    fi

    echo -n "Enter the tenant [$OS_TENANT_NAME]: "
    read response
    if [ -n "$response" ]; then
        OS_TENANT_NAME=$response
    fi
    exitloop=1
done

exitloop=0
while [ $exitloop -eq 0 ];
do
    echo -n "Enter the password: "
    read response
    if [ -n "$response" ]; then
        OS_PASSWORD=$response
        exitloop=1
    else
        echo "Password cannot be empty. Repeat. "
    fi
done

echo " * Admin user Information:"
echo "     URL:          ${OS_AUTH_URL}"
echo "     Username:     ${OS_USERNAME}"
echo "     Password:     ${OS_PASSWORD}"
echo "     Tenant:       ${OS_TENANT_NAME}"

is_keystone_admin=`__is_keystone_admin`
if [ "${is_keystone_admin}" != "True" ] ; then
    echo " * ERROR: Cannot verify keystone admin url for version v2.0. Check the url is reachable and points to v2.0 API. Then re-run the script."
    exit 1
fi
auth_token=`__get_auth_token`
if [ ! -n "${auth_token}" ] ; then
    echo " * ERROR: Cannot authenticate the admin user with url, user, tenant and password given. Check your credentials and re-run the script."
    exit 1
fi
is_portal_admin=`__is_portal_admin $auth_token`

if [ "${is_portal_admin}" != "True" ] ; then
    echo " * ERROR: The admin user does not have the role ROLE_PORTAL_ADMIN. Add this role to the admin and re-run the script."
    exit 1
fi

echo "     Auth Token:   ${auth_token}"

}
__check_keystone

__check_mysql(){
exitloop=0
while [ $exitloop -eq 0 ];
do
    echo -n "Enter the ROOT password of your MySQL installation. Empty is not allowed: "
    read response
    if [ -n "$response" ]; then
        MYSQL_ROOT_PASSWORD=$response
        exitloop=1
    else
        echo "Password cannot be empty. Repeat. "
    fi
done

echo " * MySQL ROOT information:"
echo "     Password:     ${MYSQL_ROOT_PASSWORD}"
echo " * In the post install process the installer will ask you about the connection details to MySQL"
}

if [ "${InstallMySql}" = "true" ]; then
    __check_mysql
fi

install_ubuntu_1404() {
    __configure_apt_repos "havana"
    __check_command "curl"
    if [ "${InstallMySql}" = "true" ]; then
        echo mysql-server mysql-server/root_password password $MYSQL_ROOT_PASSWORD | debconf-set-selections
        echo mysql-server mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD | debconf-set-selections
        echo mysql-server mysql-server/start_on_boot boolean true | debconf-set-selections
        __apt_get_noinput mysql-server

        echo stackops-portal stackops-portal/mysql-admin-password $MYSQL_ROOT_PASSWORD | debconf-set-selections
    fi
    if [ "${InstallApache}" = "true" ]; then
        __apt_get_noinput apache2
	__configure_apache
	service apache2 restart
    fi
    if [ "${InstallApacheWithSSL}" = "true" ]; then
        __apt_get_noinput apache2
        __configure_apache_ssl
        service apache2 restart
    fi

    echo stackops-portal stackops-portal/keystone-admin-url $OS_AUTH_URL | debconf-set-selections

    __apt_get_noinput mysql-client
    __apt_get_noinput openjdk-7-jdk
    __configure_clinker_key http://static.stackops.net/clinker.cert
    __apt_get_noinput tomcat7
    __apt_get_noinput stackops-portal
    service tomcat7 restart

}

post_install_ubuntu_1404() {
     echo "Post install service..."
}

conf_ubuntu_1404() {
    echo "configuring the portal server..."
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

install_debian_74() {
     install_ubuntu_1404
}

post_install_debian_74() {
     post_install_ubuntu_1404
}

conf_debian_74() {
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
