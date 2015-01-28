# StackOps Portal and Chargeback installer

Script for automated installation of StackOps Portal and Chargeback

## How to use it

You need a Ubuntu 12.04 Server 64 bit with 1.5GB of RAM and 10GB of disk space. Regarding the OpenStack Requirements:

- Access to Keystone Admin API endpoint
- Version 2.0 of Keystone APIs
- Access to all other service endpoints through internalURL
- Keystone admin token

StackOps Portal needs to have access to internet to download the plugins and perform live updates. You cannot install it without internet access. 

StackOps Portal and Chargeback use MySQL or MariaDB as storage backend. It can install a MySQL server on demand, or reuse an existing one. If you want to reuse an existing one, you need the root password at installation time to create the database schema and the portal user.

StackOps Portal can install an Apache server to proxy the HTTP or HTTPS requests. It installs a self-generated certificate that you should change if you want to go live with StackOps Portal.

The installer will need access to Keystone with Admin privileges to create the roles and users needed to run the components. If this is too much for you, please contact us to perform a customized installation.

##How to install StackOps Portal and Chargeback and reuse and existing MySQL server installation

`sudo bash -c "source <( curl -L goo.gl/cItQkQ ) -p -c"`

Once executed, you will have to connect to port 8080 on URI 'portal'. Example: http://yourserver:8080/portal

##How to install StackOps Portal and Chargeback and install your own MySQL server locally

`sudo bash -c "source <( curl -L goo.gl/cItQkQ ) -m -p -c"`

Once executed, you will have to connect to port 8080 on URI 'portal'. Example: http://yourserver:8080/portal

##How to install StackOps Portal and Chargeback and install your own Apache Proxy for HTTP traffic

`sudo bash -c "source <( curl -L goo.gl/cItQkQ ) -a -p -c"`

Once executed, you will have to connect to port 80. Example: http://yourserver

##How to install StackOps Portal and Chargeback  and install your own Apache Proxy for HTTPS traffic

`sudo bash -c "source <( curl -L goo.gl/cItQkQ ) -s -p -c"`

Once executed, you will have to connect to port 80 or 443, because it will always redirect to port 443. Example: http://yourserver or https://yourserver

##How to install StackOps Portal and Chargeback and Apache HTTS Traffic and local MySQL server (Whole enchilada)

`sudo bash -c "source <( curl -L goo.gl/cItQkQ ) -m -s -p -c"`

Once executed, you will have to connect to port 80 or 443, because it will always redirect to port 443. Example: http://yourserver or https://yourserver





