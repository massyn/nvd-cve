# cve
cve database

## Catchup

The "catchup" process is our way of ensuring our database is as up to date with the real thing.  We don't know everything yet - we are still catching up.

* update_catchup.py - reads the CVEListV5 data, and builds a _cvelist.txt prioritised list for us
* catchup.py - reads tht _cvelist.txt file, and does the download.  You can tweak things like
    * --max-time - how many hours it should run
    * --limit - how many objects it should retrieve
    * --min-score - the minimum score we care about
    * --filter - if we want to grab a specific type of CVE (like `CVE-2026`)
By default it will try to download everything in the txt file that we don't already have.
