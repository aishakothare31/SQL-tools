# SQL-tools
## Motivation
This tool aims at performing some sql-injection attacks and blind sql-injections on web-apps, in order to check their security level. 
As we know one of the ways to easily extract the databases fromweb applications is through SQL injections. 
The databases may contain sensitive information such passwords, login credentials and SSN, hence it is of utmost importance to detect such vulnerabilites
and sanitize the input immediately.

## Technologies Used
This tool is built using python.

## Dependancies
- Requests module
- Urllib module
- BeautifulSoup module

## Usage
python3 Sql_tool.py --url "target_url" [-db][database flag] [-t][table flag] [-c][column flag] [-b][blind sql]
