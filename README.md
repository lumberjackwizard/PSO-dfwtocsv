# PSO-dfwtocsv


At script initiation, user will be prompted to enter the NSX Manager FQDN or IP address, followed by a username and password. 

A menu will be displayed, offering 3 options:

1- Display a full list of all user-created policy names
2- Allow user to search for specific polices and associated rules to output to a csv file
3- Gather all polices and associated rules and output to a file

Notes:

1) The search function is using a -like switch; this allows for a user to grab any policy name that has a given word, like "NTP". If muliple policies match the search criteria, all are inserted in the CSV.

2) An entire policy name can still be entered to narrow the selections to a specific policy. The search feature is case insensitive.

3) Each interation of option 2 or 3 will result in a csv file named policy_<timestamp>.csv. The timestamp is in yyyyMMdd_HHmmss format. 

4) After a successful complettion of options 1-3, the user is returned to the main menu, where other options can be ran or the script can be exited via the 'Q' selection on the menu. 

Note: Configured script to replace a Context Profile entry with a blank line rather than the "ANY" that is actually captured from the API get. This was to make it clearer in the CSV that when no context profile is configured for a given rule. 

When Context Profiles ARE used, they are captured and displayed appropriately. 