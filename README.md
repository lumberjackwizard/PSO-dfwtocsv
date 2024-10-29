# PSO-dfwtocsv

Performs a single API request to a target NSX Manager to gather elements of a selected security policy. 

At script initiation, user will be prompted to enter the NSX Manager FQDN or IP address, followed by a username and password. 

User will then be prompted to enter the name of the target Security policy. Upon a successful match, the policy and all of it's rules are output to a CSV file. 

If there's no matching policy, an error message will be placed onscreen, and the user will be prompted to enter a security policy again. 

Notes:

1) The search function is using a -like switch; this allows for a user to grab any policy name that has a given word, like "NTP". If muliple policies match the search criteria, all are inserted in the CSV.
2) It's possible to use an -eq switch for the search, but this would mean a given policy name would need to be entered perfectly to find a match.
3) An entire policy name can still be entered to narrow the selections to a specific policy. The search feature is case insensitive.
