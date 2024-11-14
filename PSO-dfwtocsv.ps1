# Developed on Powershell 7.4.5 


#Gathering NSX Manager and Credentials
$nsxmgr = Read-Host "Enter NSX Manager IP or FQDN"
$Cred = Get-Credential -Title 'NSX Manager Credentials' -Message 'Enter NSX Username and Password'


function Invoke-Check-NSX-Credentials(){
	$checkUri = 'https://'+$nsxmgr+'/policy/api/v1/infra'

	#using Invoke-WebRequst to evaluate the statuscode that is returned from the NSX Manager
	$response = Invoke-WebRequest -Uri $checkUri -Method Get -SkipCertificateCheck -Authentication Basic -Credential $Cred -SkipHttpErrorCheck
	
	if ($response.StatusCode -eq 200) {
		Write-Host "Successfully connected to NSX Manager. Status: 200 OK"
	} else {
		Write-Host "Failed to connect to NSX Manager." 
		Write-Host "Status: $($response.StatusCode)"
		Write-Host "Error Message:" ($response.Content)
		Write-Host "Exiting script... Please try again. "
		exit
	}

}


function Get-UserInput(){
	$userinput = Read-Host "Enter Security Policy Name (or hit the 'Enter' key to be prompted to quit)"
	if ($userinput -eq ""){
	 	$tryAgain = Read-Host "Nothing was entered. Do you want to try again? <Y/N>"
		if ($tryAgain -eq "y" -or $tryAgain -eq "Y"){
			continue
		} elseif ($tryAgain -eq "n" -or $tryAgain -eq "N"){
			New-OutputNSXCSV
			exit
		} else {
			Write-Host "Invalid input, please enter Y or N."
		}
	}
		
	
	return $userinput.Trim()

}


function Get-NSXDFW($Uri){


	
	# The below gathers all securitypolicies, groups, and context profiles from infra, storing it in 
	# the $rawpolicy variable 
	# Services are captured in the rawSvcPolicy variable. I've experinced issues when grabbing everything (including services)
	# directly into rawpolicy when using PowerShell 7.x on Windows. When using PowerShell 7.x on Ubuntu, everything works. 
	# To that end, I opted for 2 API calls so everything will work properly regardless of OS. 

	Write-Host "Requesting data from target NSX Manager..."

	$rawpolicy = Invoke-RestMethod -Uri $Uri -SkipCertificateCheck -Authentication Basic -Credential $Cred 
	$rawSvcPolicy = Invoke-RestMethod -Uri $SvcUri -SkipCertificateCheck -Authentication Basic -Credential $Cred 
	
	
	# Gathering security policies
	
	$secpolicies = $rawpolicy.children.Domain.children.SecurityPolicy | Where-object {$_.id -And $_.id -ne 'Default'} | Sort-Object -Property sequence_number
	
	

	

	# Gathering Groups

	$allgroups = $rawpolicy.children.Domain.children.Group | Where-object {$_.id}
	
	#Gathering Services

	$allservices = $rawSvcPolicy.children.Service | Where-object {$_.id}
	
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
	if (-not $newfilteredrules){
    	$newfilteredrules = "DFW Tab,POLICY NAME,RULE NAME,ID,Sources,Destinations,Services,Context Profiles,Applied To,Action,Logging,Comments `n"
	}

	$policyMatch = 0
	foreach ($secpolicy in $allsecpolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}){
		if ($secpolicy.display_name -like "*$userinput*"){
			$policyMatch = 1
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
					foreach ($filteredgroup in $allsecgroups){
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
	if ($policyMatch -eq 0){
		Write-Host "No match for: " $userinput
	}
	
	#Finishing out the function by taking the complete $newfilteredrules variable (containing all rules in CSV format)
	# and returning the result. 

    return $newfilteredrules
	
	
}


function New-OutputNSXCSV {
	if (-not $newfilteredrules -or ($newfilteredrules.EndsWith("Comments `n"))){
		Write-Host "No data gathered. No file will be created."
		exit
	} else {
		Write-Host "Generating output file 'policy.csv'..."
		$newfilteredrules | Out-File -FilePath .\policy.csv
	}

}

function Build-CSV(){

	while (-not $newfilteredrules -or ($newfilteredrules.EndsWith("Comments `n") -or ($oldlinecount -eq $newlinecount)) ){

		#Prompt the user for the target Security Group
		$userinput = Get-UserInput
		$oldlinecount = ($newfilteredrules -split "`n").Count
		

		$newfilteredrules += Get-Target-Policy -allsecpolicies $allsecpolicies -allsecgroups $allsecgroups -allsecservices $allsecservices -allseccontextprofiles $allseccontextprofiles -userinput $userinput

		
		$selectedlinecount = ($newfilteredrules -split "`n").Count
		

		$newlinecount = $selectedlinecount + $oldlinecount
		
	}
	return $newfilteredrules
}

function Add-More-Policies(){
	while ($additionalPolicies -ne 'Y' -and $additionalPolicies -ne 'y' -and $additionalPolicies -ne 'N' -and $additionalPolicies -ne 'n') {

		$additionalPolicies = Read-Host "Would you like to add additional Security Policies to the csv file? <Y/N>"
	
		if ($additionalPolicies -eq "y" -or $additionalPolicies -eq "Y"){
			
			$newfilteredrules += Build-CSV
	
			$additionalPolicies = ""
			
			
		} elseif ($additionalPolicies -eq "n" -or $additionalPolicies -eq "N"){
			Write-Host "`n"
		} else {
			Write-Host "Invalid input, please enter Y or N."
		}
	}

	return $newfilteredrules
}

# Main 

# Get-UserInput is used to prompt and gather the desired policy name
# $newfilteredrules is populated with the returned $newfilteredrules variable from the Get-NSXDFW function. The data 
# gathered from Get-UserInput is used to find the specific policy. 
# If there's no match, diagnostic data is presented to the user, and the Get-UserInput and Get-NSXDFW functions are ran again.
# Finally, the New-OutputNSXCSV function outputs the data into the policy.csv file


# Uri will get only securitypolices, groups, context profiles under infra
# SvcUri will get only services. 

$Uri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=SecurityPolicy;Group;PolicyContextProfile'
$SvcUri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=Service'

Invoke-Check-NSX-Credentials


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

$newfilteredrules = Build-CSV

$newfilteredrules += Add-More-Policies




New-OutputNSXCSV
