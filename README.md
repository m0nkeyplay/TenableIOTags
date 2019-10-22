# TenableIOTags
Let's get asset and vulnerability info from Tenable IO based on tags.

These tags are an elusive thing promised by SEs for a while now and I found a use for them, when they work.

Using some of the workbench API calls this will pull down asset data based on a predefined tag and vulnerabilites associated with it.

This script only requires keys (so access to the data) and requests.  No other modules are required.

*usage* `python vulnsByTag.py -d DaysBack -t TagName -v TagValue`

This is v1.1 

Less things are hardcoded in.

******notes:******      These variables are important.  Complete/change them.

               pickup_file     <-- Where the export data goes to be picked up
               ak              <-- Access Key
               sk              <-- Secret Key
               proxies         <-- If you use a proxy, set it here.
