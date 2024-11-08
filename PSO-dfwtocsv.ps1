# Developed on Powershell 7.4.5 

# Temporarily hard setting nsxmgr and credentials for development. Get-Credential will be used in the future. 

$nsxmgr = '172.16.10.11'
$nsxuser = 'admin'
$nsxpasswd = ConvertTo-SecureString -String 'VMware1!VMware1!' -AsPlainText -Force
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $nsxuser, $nsxpasswd


#$nsxmgr = Read-Host "Enter NSX Manager IP or FQDN"
#$Cred = Get-Credential -Title 'NSX Manager Credentials' -Message 'Enter NSX Username and Password'

# Uri will get only securitypolices, groups, context profiles and services under infra

$Uri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=SecurityPolicy;Group;PolicyContextProfile;Service'

function Get-UserInput(){
	$userinput = Read-Host "Enter Security Policy Name"
	return $userinput.Trim()

}


function Get-NSXDFW($Uri){


	
	# The below gathers all securitypolicies, groups, and services from infra, storing it in 
	# the $rawpolicy variable 

	Write-Host "Requesting data from target NSX Manager..."

	$rawpolicy = Invoke-RestMethod -Uri $Uri -SkipCertificateCheck -Authentication Basic -Credential $Cred 
	
	
	# Gathering security policies
	
	$secpolicies = $rawpolicy.children.Domain.children.SecurityPolicy | Where-object {$_.id -And $_.id -ne 'Default'} | Sort-Object -Property sequence_number
	

	# Gathering Groups

	$allgroups = $rawpolicy.children.Domain.children.Group | Where-object {$_.id}
	
	#Gathering Services

	$allservices = $rawpolicy.children.Service | Where-object {$_.id}
	
	# Gathering Context Profiles

	$allcontextprofiles = $rawpolicy.children.PolicyContextProfile | Where-object {$_.id}

	return [pscustomobject]@{
        SecPolicies =        $secpolicies
		AllGroups   =        $allgroups
		AllServices =        $allservices
		AllContextProfiles = $allcontextprofiles
    }
}


function Get-Target-Policy(){
	param (
		[PSCustomObject]$allsecpolicies,
		[PSCustomObject]$allsecgroups,
		[PSCustomObject]$allsecservices,
		[PSCustomObject]$allseccontextprofiles,
		[string]$userinput
	)

	#Below checks for a match of the user entered policy name via an if statement. 

    $newfilteredrules = "DFW Tab,POLICY NAME,RULE NAME,ID,Sources,Destinations,Services,Context Profiles,Applied To,Action,Logging,Comments `n"


	foreach ($secpolicy in $allsecpolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}){
		#Write-Host "secpolicy display name is" $secpolicy.display_name
		if ($secpolicy.display_name -like "*$userinput*"){
			Write-Host "Matching Security Policy: "$secpolicy.display_name
			$sortrules = $secpolicy.children.Rule | Sort-Object -Property sequence_number
		

			foreach ($rule in $sortrules | Where-object {$_.id}){
				
				$rulecategory = $secpolicy.category
				$rulepolicyname = $secpolicy.display_name
				$ruleid = $rule.rule_id
				$ruleentryname = $rule.display_name
				$ruleentryaction = $rule.action
				$rulelogging = $rule.logged
				$rulecomments = $rule.notes
		
				$initruleentrysrc = @()
				$initruleentrydst = @()
				$initruleentrysvc = @()
				$initruleentrycxtpro = @()
				$initruleentryappliedto = @()

				#The next 5 for loops are designed to gather the more readable display name for a group/svc/contect profile. 
				#It does this by comparing the entry from the rule to the .path entry for each group. 
				#If there's no match, the entry itself is used; this would be for the case of somethign like an "ANY" as an entry,
				# as it would not be a "group". 

				#Getting display name for each member of the source field in a rule

				foreach ($srcgroup in $rule.source_groups){
					$n = 0
					foreach ($filteredgroup in $allsecgroups){
						if ($filteredgroup.path -eq $srcgroup){
							$initruleentrysrc += $filteredgroup.display_name 
							$n = 1
							break
						}
						
					}
					if ($n -eq "0") {
						$initruleentrysrc += $srcgroup 
						}	
				}
				
				 $ruleentrysrc =  ($initruleentrysrc | Sort-Object) -join ", "
			
				#Getting display name for each member of the destination field in a rule
				
				foreach ($dstgroup in $rule.destination_groups){  
					$n = 0
					foreach ($filteredgroup in $allsecgroups){
						if ($filteredgroup.path -eq $dstgroup){
							$initruleentrydst += $filteredgroup.display_name #+ ","
							$n = 1
							break
						}
						
					}
					if ($n -eq "0") {
						$initruleentrydst += $dstgroup 
					}
				}	

				$ruleentrydst =  ($initruleentrydst | Sort-Object) -join ", "

				#Getting display name for each member of the service field in a rule

				foreach ($svcgroup in $rule.services){ 
					$n = 0
					foreach ($filsvc in $allsecservices){
						if ($filsvc.path -eq $svcgroup){
							$initruleentrysvc += $filsvc.display_name 
							$n = 1
							break
						}
						
					}
					if ($n -eq "0") {
						$initruleentrysvc += $svcgroup 
					}							
				}
				
				$ruleentrysvc =  ($initruleentrysvc | Sort-Object) -join ", "
			
				#Getting display name for each member of the context profile field in a rule

				foreach ($cxtprogroup in $rule.profiles){  
					$n = 0
					foreach ($filctxpro in $allseccontextprofiles){
						if ($filctxpro.path -eq $cxtprogroup){
							$initruleentrycxtpro += $filctxpro.display_name 
							$n = 1
							break
						}
						
					}
					if ($n -eq "0") {
						$initruleentrycxtpro += $cxtprogroup 
					}
				}

				$ruleentrycxtpro =  ($initruleentrycxtpro | Sort-Object) -join ", "

				#Getting display name for each member of the applied-to field in a rule
			
				foreach ($appliedtogroup in $rule.scope){
					$n = 0
					foreach ($filteredgroup in $allgroups){
						if ($filteredgroup.path -eq $appliedtogroup){
							$initruleentryappliedto += $filteredgroup.display_name 
							$n = 1
							break
						}
						
					}
					if ($n -eq "0") {
						$initruleentryappliedto += $appliedtogroup 
						}	
				}
				
				$ruleentryappliedto =  ($initruleentryappliedto | Sort-Object) -join ", "

				#The below adds double quotes around the full member list of each entry. This ensures in a CSV, multiple
				# entries for a source, for instance, all stay under the "source" column header

				$ruleentrysrc = "`"$ruleentrysrc`""
				$ruleentrydst = "`"$ruleentrydst`""
				$ruleentrysvc = "`"$ruleentrysvc`""
				$ruleentrycxtpro = "`"$ruleentrycxtpro`""
				$ruleentryappliedto = "`"$ruleentryappliedto`""

			

				#This is where we construct each line of the csv, ending with a newline
				$rules = $rulecategory, $rulepolicyname, $ruleentryname, $ruleid, $ruleentrysrc, $ruleentrydst, $ruleentrysvc, $ruleentrycxtpro, $ruleentryappliedto, $ruleentryaction, $rulelogging, $rulecomments -join ","
				$rules += "`n"


				#adding each rule to the $newfilteredrules variable
				$newfilteredrules += $rules
				
				
			}  
			$newfilteredrules += "	  `n"    
		
		} 
	}	
	
	#Finishing out the function by taking the complete $newfilteredrules variable (containing all rules in CSV format)
	# and returning the result. 

    return $newfilteredrules
	
	
}


function New-OutputNSXCSV {

	Write-Host "Generating output file..."
    $newfilteredrules | Out-File -FilePath .\policy.csv

}



# Main 

# Get-UserInput is used to prompt and gather the desired policy name
# $newfilteredrules is populated with the returned $newfilteredrules variable from the Get-NSXDFW function. The data 
# gathered from Get-UserInput is used to find the specific policy. 
# If there's no match, diagnostic data is presented to the user, and the Get-UserInput and Get-NSXDFW functions are ran again.
# Finally, the New-OutputNSXCSV function outputs the data into the policy.csv file

# $displayList = Read-Host "Would you like to display a list of all Security Policy Names? <Y/N>"

# if ($displayList -like "y"){
# 	Write-Host 
# } 

$allpolicies = Get-NSXDFW($Uri)

$allsecpolicies = $allpolicies.SecPolicies
$allsecgroups = $allpolicies.AllGroups
$allsecservices = $allpolicies.AllServices
$allseccontextprofiles = $allpolicies.AllContextProfiles

#Prompt user to see if they want a full list of existing Security Policies

while ($displayList -ne 'Y' -and $displayList -ne 'y' -and $displayList -ne 'N' -and $displayList -ne 'n') {

	$displayList = Read-Host "Would you like to first display a list of all Security Policy Names? <Y/N>"

	if ($displayList -eq "y" -or $displayList -eq "Y"){

		foreach ($secpolicyname in $allsecpolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}){
			Write-Host $secpolicyname.display_name
		}
		Write-Host "`n"
	} elseif ($displayList -eq "n" -or $displayList -eq "N"){
		Write-Host "`n"
	} else {
		Write-Host "Invalid input, please enter Y or N."
	}
}

#Prompt the user for the target Security Group
$userinput = Get-UserInput


$newfilteredrules = Get-Target-Policy -allsecpolicies $allsecpolicies -allsecgroups $allsecgroups -allsecservices $allsecservices -allseccontextprofiles $allseccontextprofiles -userinput $userinput

if ($newfilteredrules.EndsWith("Comments `n")) {
	write-host "No policy matches: $userinput"
	write-host "Please try again or break with Ctrl-C"
	write-host "`n"
	$userinput = Get-UserInput

	

	$newfilteredrules = Get-NSXDFW($Uri)

}

New-OutputNSXCSV
