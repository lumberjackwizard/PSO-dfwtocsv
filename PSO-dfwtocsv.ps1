# Developed on Powershell 7.4.5 


#Gathering NSX Manager and Credentials
$nsxmgr = Read-Host "Enter NSX Manager IP or FQDN"
$Cred = Get-Credential -Title 'NSX Manager Credentials' -Message 'Enter NSX Username and Password'


function Invoke-CheckNSXCredentials(){
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
	param(
		[string] $additionalPolicies
	)

	$userinput = Read-Host "Enter Security Policy Name (or hit the 'Enter' key to be prompted to quit)"
	if ($userinput -eq ""){
	 	$tryAgain = Read-Host "Nothing was entered. Do you want to try again? <Y/N>"
		if ($tryAgain -eq "y" -or $tryAgain -eq "Y"){
			continue
		} elseif ($tryAgain -eq "n" -or $tryAgain -eq "N"){
			if ($additionalPolicies -eq 1) {
				#needed a unique name that is unlikely to match a policy name
				#this acts as a marker in case a user has selected to add additional policies 
				#but opts during the process to choose hit 'Enter' to quit the policy name search
				$userinput = "Pi is 3.1415"
				return $userinput
			} else {
				Invoke-CreateMenu
				exit
			}
		} else {
			Write-Host "Invalid input, please enter Y or N."
		}
	}	
	
	return $userinput.Trim()
}


function Get-NSXDFW(){


	
	# The below gathers all securitypolicies, groups, and context profiles from infra, storing it in 
	# the $rawpolicy variable 
	# Services are captured in the rawSvcPolicy variable. I've experinced issues when grabbing everything (including services)
	# directly into rawpolicy when using PowerShell 7.x on Windows. When using PowerShell 7.x on Ubuntu, everything works. 
	# To that end, I opted for 2 API calls so everything will work properly regardless of OS. 

	Write-Host "Requesting data from target NSX Manager..."
	Write-Host "`n"

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


function Get-TargetPolicy(){
	param (
		[PSCustomObject]$allsecpolicies,
		[PSCustomObject]$allsecgroups,
		[PSCustomObject]$allsecservices,
		[PSCustomObject]$allseccontextprofiles,
		[string]$userinput
	)
	#this first if looks for the name that is automatically entered by the Get-UserInput function when they opt
	#to give up on searching for an additional policy name. This simply returns a space to the function that has
	#called the Get-TargetPolicy function. 
	#Without the return of the space, an unusual phenomenon occurs where the first policy pulled (before the additional polices prompt)
	#gets duplicated in the output file twice. 
	if ($userinput -eq "Pi is 3.1415"){
		return " "
	} else {
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
					$newmatchedrules += $rules
					
					
				}  
				$newmatchedrules += "	  `n"    
			
			} 
		}	
		if ($policyMatch -eq 0){
			Write-Host "No match for: " $userinput
			Write-Host "Please try again"

		}
	
	#Finishing out the function by taking the complete $newfilteredrules variable (containing all rules in CSV format)
	# and returning the result. 

		return $newmatchedrules
	}
	
}


function Invoke-OutputNSXCSV {

	param (
		[string]$outputFile
	)

	if (-not $newfilteredrules -or ($newfilteredrules.EndsWith("Comments `n"))){
		Write-Host "No data gathered. No file will be created."
		exit
	} else {
		Write-Host "Generating output file '$outputFile'..."
		$newfilteredrules | Out-File -FilePath .\$outputFile
	}

}

function Invoke-BuildCSV(){

	param ( 
		[string] $getAllPolicies,
		[string] $additionalPolicies
	)

	while (-not $newfilteredrules -or ($newfilteredrules.EndsWith("Comments `n") -or ($oldlinecount -eq $newlinecount)) ){

		#Prompt the user for the target Security Group
		#if the getAllPolicies switch is used (Option 3 in the menu), the "" that is returned for $userinput
		#will successfully match against all policies
		if ($getAllPolicies -eq "1"){
			$userinput = ""
		#The elseif is to ensure the Get-UserInput gets the -additionalPolicies switch sent along with the Get-UsernInput request
		#This is to handle the situation where a user has elected to add additional polices but opts to hit enter and then stop the 
		#search by entering 'No'. 
		} elseif ($additionalPolicies -eq "1") {
			$userinput = Get-UserInput -additionalPolicies "1"
		} else {
			$userinput = Get-UserInput
		}



		$oldlinecount = ($newfilteredrules -split "`n").Count
		
		
		
		$newfilteredrules += Get-TargetPolicy -allsecpolicies $allsecpolicies -allsecgroups $allsecgroups -allsecservices $allsecservices -allseccontextprofiles $allseccontextprofiles -userinput $userinput
		
		
		$selectedlinecount = ($newfilteredrules -split "`n").Count

		

		$newlinecount = $selectedlinecount + $oldlinecount

		
	}
	return $newfilteredrules
}

function Invoke-AddAdditionalPolicies(){
	while ($additionalPolicies -ne 'Y' -and $additionalPolicies -ne 'y' -and $additionalPolicies -ne 'N' -and $additionalPolicies -ne 'n') {

		$additionalPolicies = Read-Host "Would you like to add additional Security Policies to the csv file? <Y/N>"
	
		if ($additionalPolicies -eq "y" -or $additionalPolicies -eq "Y"){
			
			$additionalRules += Invoke-BuildCSV -additionalPolicies "1"
	
			$additionalPolicies = ""
			
			
		} elseif ($additionalPolicies -eq "n" -or $additionalPolicies -eq "N"){
			Write-Host "`n"
		} else {
			Write-Host "Invalid input, please enter Y or N."
		}
	}

	return $additionalRules
}

function Show-MainMenu
{
     param (
           [string]$Title = ‘NSX DFW Security Policies to CSV’
     )
     
	 Write-Host "`n"
     Write-Host “================ $Title ================”
     
     Write-Host “1: Press ‘1’ to display a list of all existing Security Policies.”
     Write-Host “2: Press ‘2’ to search for specific Security Policies and input them and their associated rules into a csv file.”
	 Write-Host “3: Press ‘3’ to output all Security Policies and associated rules into a csv file.”
     Write-Host “Q: Press ‘Q’ to quit.”
}

function Invoke-CreateMenu {
	do
	{
		Show-MainMenu
		$input = Read-Host “Please make a selection”
		switch ($input)
		{
			‘1’ {
					
					‘Displaying a list of all Security Policies...’
					''
					foreach ($secpolicyname in $allsecpolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}){
						Write-Host $secpolicyname.display_name
					}
					''
			} ‘2’ {
					
					$newfilteredrules = Invoke-BuildCSV
					$newfilteredrules += Invoke-AddAdditionalPolicies

					$timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
					$outputFile = "policy_$timestamp.csv"
					Invoke-OutputNSXCSV -outputFile $outputFile
					'Done!'
			} ‘3’ {
				
					‘Gathering all security policies and rules ...’
					$newfilteredrules = Invoke-BuildCSV -getAllPolicies "1"

					$timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
					$outputFile = "policy_$timestamp.csv"
					Invoke-OutputNSXCSV -outputFile $outputFile
					'Done!'
			} ‘q’ {
					return
			}
		}
		pause
	}
	until ($input -eq ‘q’)

}

# Main 



Invoke-CheckNSXCredentials


# Uri will get only securitypolices, groups, context profiles under infra
# SvcUri will get only services. Each of these are used in the Get-NSXDFw function
$Uri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=SecurityPolicy;Group;PolicyContextProfile'
$SvcUri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=Service'

$allpolicies = Get-NSXDFW

$allsecpolicies = $allpolicies.SecPolicies
$allsecgroups = $allpolicies.AllGroups
$allsecservices = $allpolicies.AllServices
$allseccontextprofiles = $allpolicies.AllContextProfiles

# Generate Menu


Invoke-CreateMenu


