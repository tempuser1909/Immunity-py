This script supports the SQLOLEDB method of executing queries and, when combined with sql_listener.py will send you all the queries executed by a web application. Server-side filtering (necessary to avoid sending thousands of queries a second to you on a busy server) is stubbed in for later. We hooked IIS rather than SQL Server because common practice is to have your SQL tier un-routable, but the web tier is likely to have Internet access.

Somewhat later we'll have this integrate into SPIKE Proxy and other tools to automate detection of blind-sql attacks/detection and sql injection in general.

In order to use this script:

1. Run a few queries against your target server, this will start up two dllhost.exe's
2. Load Immunity Debugger and attach to the second dllhost.exe (this can be slightly tricky if the PID for the second one is lower than the first, but eventually we'll automate it)
3. run !sqlhooker -s myhostip:myport. For example, I use !sqlhooker 192.168.1.1:8081, and then on my .1 machine I run "python sql_listener.py 8081".



Here's an example snippet of ASP script this would work against:

_start cut_
set conn = server.createObject("ADODB.Connection")
set rs = server.createObject("ADODB.Recordset")



query = "select count(*) from users where userName='" & userName & "' and userPass='" & password & "'"
conn.Open "Provider=SQLOLEDB; Data Source=(local); Initial Catalog=myDB; User Id=sa; Password="
rs.activeConnection = conn
rs.open query
_end cut_

We currently support:

WinXPPro Sp2, IIS 5.0 SQLServer 2000
Win2K3, IIS 6.0, SQLServer 2000
Win2K, IIS 5.0, SQLServer 2000
Win2K Old,IIS 5.0, SQLServer 2000