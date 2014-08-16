$script:username = $null
$script:APIKey = $null

function Get-RSAuth(){
    param(
        [Parameter(Mandatory=$True,ParameterSetName='UsernameAuth')][string]$Username,
        [Parameter(Mandatory=$True,ParameterSetName='UsernameAuth')][string]$APIKey,
        [Parameter(Mandatory=$True,ParameterSetName='TokenAuth')][string]$DDI,
        [Parameter(Mandatory=$True,ParameterSetName='TokenAuth')][string]$APIToken
    )

    $date = Get-Date 

    #If ($date -GT $RSTokenExpiry -or $RSTokenExpiry -eq $null){
        $identityURI = "https://identity.api.rackspacecloud.com/v2.0/tokens"
        $credJson = @{"auth" = @{"RAX-KSKEY:apiKeyCredentials" =  @{"username" = $UserName; "apiKey" = $APIKey}}} | convertTo-Json
        $catalog = Invoke-RestMethod -Uri $identityURI -Method POST -Body $credJson -ContentType application/json

        $serviceCatalog = @{}
        foreach ($line in $catalog.access.serviceCatalog) {
            $endpoints = $null
            if ($line.endpoints[0].region -eq $null) { 
               $endpoints = $line.endpoints[0].publicURL 
            } else {
                $endpoints=@{}
                foreach ($endpoint in $line.endpoints) { $endpoints.add($endpoint.region,$endpoint.publicURL) }
            }
            $serviceCatalog.add($line.name,$endpoints)
        }

        $auth = @{
            "Username"="$username";
            "apiKey"="$apiKey";
            "DDI"="$($catalog.access.token.tenant.id)";
            "APIToken"="$($catalog.access.token.id)";
            "json"="$($catalog | ConvertTo-Json -depth 10)";
            "catalog"=$serviceCatalog;
            "TokenExpiry"=[datetime]$catalog.access.token.expires
        }
        #$catalog | Add-Member username $username  
        #$catalog | Add-Member apikey $APIKey
        #$catalog | Add-Member DDI $catalog.access.token.tenant.id
        #$catalog | Add-Member APIToken $catalog.access.token.id
    #}

    $auth
} 

function Check-RSAuth(){
        write-host "DDI: $script:DDI"
        write-host "Token Expiration: $script:TokenExpiry"
        write-host "API Key: $script:APIKey"
        write-host "API Token: $script:APIToken"
        write-host "Username: $script:Username"
}


function Clear-RSAuth(){
        $script:DDI = $null
        $script:TokenExpiry = $null
        $script:APIKey = $null
        $script:APIToken = $null
        $script:Username = $null
        $script:ServiceCatalog = $null
}

function Get-RSNextGenServer(){
   #[CmdletBinding(DefaultParametersetName="RSServerSearch")] 
    param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)][string]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)][string]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ParameterSetName='RSServerDetail')]$ServerID,
        [Parameter(ParameterSetName='RSServerSearch')][switch]$DetailedList,
        [Parameter(ParameterSetName='RSServerSearch')]$Image,
        [Parameter(ParameterSetName='RSServerSearch')]$Flavor,
        [Parameter(ParameterSetName='RSServerSearch')]$Name,
        [Parameter(ParameterSetName='RSServerSearch')]$Status,
        [Parameter(ParameterSetName='RSServerSearch')]$Marker,
        [Parameter(ParameterSetName='RSServerSearch')]$Limit,
        [Parameter(ParameterSetName='RSServerSearch')]$ChangeDate,
        [Parameter(ParameterSetName='RSServerSearch')]$ImageScheduled
    ) 

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers"
    $authToken = @{"X-Auth-Token"=$APIToken}

    if ($PsCmdlet.ParameterSetName -eq "RSServerDetail"){
        $uri = $uri + "/$ServerId"
        write-debug "Calling: $uri"
        $catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $authToken -ContentType application/json
        return $catalog.server 
    } else {

        $params= @()
        if ($detailedList.IsPresent) { $uri = $uri+"/detail" }
        if ($ImageID -ne $null) { $params += "image=$ImageID" }
        if ($FlavorID -ne $null) { $params += "flavor=$FlavorID" }
        if ($Name -ne $null) { $params += "name=$Name" }
        if ($Status -ne $null) { $params += "status=$Status" }
        if ($Marker -ne $null) { $params += "marker=$Marker" }
        if ($Limit -ne $null) { $params += "limit=$Limit" }
        if ($ChangeDate -ne $null) { $params += "changes-since=$ChangeDate" }
        if ($ImageScheduled -ne $null) { $params += "RAX-SI:image_schedule=$ImageScheduled" }
        $p = $params -join "&"
        if ($p -ne "") { $uri = $uri + "?$p" }
        write-debug "Calling: $uri"

        $catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $authToken -ContentType application/json
        $catalog.servers = $catalog.servers | Add-Member -MemberType NoteProperty -Name DC -Value $DC -PassThru -Force
        $catalog.servers = $catalog.servers | Add-Member -MemberType NoteProperty -Name DDI -Value $DDI -PassThru -Force
        $catalog.servers = $catalog.servers | Add-Member -MemberType NoteProperty -Name APIToken -Value $APIToken -PassThru -Force
        $catalog.servers = $catalog.servers | Add-Member -MemberType AliasProperty -Name ServerId -Value ID -PassThru -Force
        $catalog.servers = $catalog.servers | Add-Member -MemberType AliasProperty -Name ImageID -Value image.ID -PassThru -Force
        $catalog.servers = $catalog.servers | Add-Member -MemberType AliasProperty -Name FlavorID -Value flavor.ID -PassThru -Force

        return $catalog.servers
    }



    #Get Load Balancer Details
    #$catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $authToken -ContentType application/json
    #$catalog.servers | ConvertTo-Json
}

function Update-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter()]$Name, 
        [Parameter()]$AccessIPv4,
        [Parameter()]$AccessIPv6
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    $body = @{"server" =  @{}}

    if ($Name -ne $null) { 
    
        $body.server.add("name",$Name)
    } 
     if ($AccessIPv4 -ne $null) { 
        
        $body.server.add("accessIPv4",$AccessIPv4)
    } 
     if ($AccessIPv6 -ne $null) { 
        
        $body.server.add("accessIPv6",$AccessIPv6)
    } 
    $body = $body | ConvertTo-Json
    #$body
    write-debug "Calling: $uri"
    $catalog = Invoke-RestMethod -Uri ($uri) -Method PUT -Body $body -Headers $authToken -ContentType application/json
    return $catalog.server
}

function New-RSNextGenServer(){
[CmdletBinding(DefaultParametersetName="AutoDisk")] 
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$Flavor,
        [Parameter(Mandatory=$True,Position=4)]$Name,
        [Parameter(Mandatory=$True,Position=5)]$Image,
        [Parameter(ParameterSetName='AutoDisk')][switch]$AutoDisk,
        [Parameter(ParameterSetName='ManualDisk')][switch]$ManualDisk,
        [Parameter()]$Metadata, 
        [Parameter()]$Personality,
        [Parameter()]$Networks, 
        [Parameter()]$KeyPair 
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    $body = @{"server" =  @{"name" = "$Name";"imageRef" = "$image";"flavorRef" = "$Flavor"}}

    if ($AutoDisk.IsPresent) { 
        $body.server.add("config_drive", $true) 
        $body.server.add("OS-DCF:diskConfig", "AUTO") 
    }
    if ($ManualDisk.IsPresent) { 
        $body.server.add("config_drive", $true) 
        $body.server.add("OS-DCF:diskConfig", "MANUAL") 
    }
    if ($Metadata.count -gt 0) { 
        $body.server.add("metadata", $metaData) 
    }
    if ($personality.count -gt 0) { 
        $body.server.add("metadata", $metaData) 
    }
    if ($networks.count -gt 0) { 
        $body.server.add("metadata", $metaData) 
    }
    if ($KeyPair -ne $null) { 
        $body.server.add("keypair", @{"key_name" = "$keyPair"})  
    }

    $body = $body | ConvertTo-Json
    write-debug "Calling: $uri"
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
    return $catalog.server
}

function Delete-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$ServerID"

    $authToken = @{"X-Auth-Token"=$APIToken}
    write-debug "Calling: $uri"
    $catalog = Invoke-RestMethod -Uri ($uri) -Method DELETE -Headers $authToken -ContentType application/json
}

function ChangeAdminPass-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$AdminPass
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    $body = @{"changePassword" =  @{"adminPass" = "$AdminPass"}} | convertTo-Json 
    write-debug "Calling: $uri"
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
}

function Reboot-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter()][switch]$HardReboot
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    if ($HardReboot.IsPresent) { 
        $body = @{"reboot" =  @{"type" = "HARD"}} | convertTo-Json 
    } else {
        $body = @{"reboot" =  @{"type" = "SOFT"}} | convertTo-Json 
    }
    write-debug "Calling: $uri"
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
}

function Rebuild-RSNextGenServer(){
[CmdletBinding(DefaultParametersetName="AutoDisk")] 
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$Image,
        [Parameter()]$Name,
        [Parameter(ParameterSetName='AutoDisk')][switch]$AutoDisk,
        [Parameter(ParameterSetName='ManualDisk')][switch]$ManualDisk,
        [Parameter()]$Metadata, 
        [Parameter()]$Personality,
        [Parameter()]$AdminPass 
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    $body = @{"rebuild" =  @{"imageRef" = "$image"}}

    if ($Name -ne $null) { 
        $body.rebuild.add("name",$Name)
    }
    if ($AutoDisk.IsPresent) { 
        $body.rebuild.add("config_drive", $true) 
        $body.rebuild.add("OS-DCF:diskConfig", "AUTO") 
    }
    if ($ManualDisk.IsPresent) { 
        $body.rebuild.add("config_drive", $true) 
        $body.rebuild.add("OS-DCF:diskConfig", "MANUAL") 
    }
    if ($Metadata.count -gt 0) { 
        $body.rebuild.add("metadata", $metaData) 
    }
    if ($personality.count -gt 0) { 
        $body.rebuild.add("metadata", $metaData) 
    }
    if ($adminPass -ne $null) { 
        $body.rebuild.add("adminPass", $AdminPass)  
    }

    $body = $body | ConvertTo-Json
    #$body
    write-debug "Calling: $uri"
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
    return $catalog.server
}

function Resize-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$FlavorID,
        [Parameter(ParameterSetName='AutoDisk')][switch]$AutoDisk,
        [Parameter(ParameterSetName='ManualDisk')][switch]$ManualDisk
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    if ($AutoDisk.IsPresent) { 
        $body = @{"resize" =  @{"flavorRef" = "$flavorID";"OS-DCF:diskConfig" = "AUTO"}} | convertTo-Json 
    } elseif ($ManualDisk.IsPresent) {
        $body = @{"resize" =  @{"flavorRef" = "$flavorID";"OS-DCF:diskConfig" = "MANUAL"}} | convertTo-Json 
    } else {
        $body = @{"resize" =  @{"flavorRef" = "$flavorID"}} | convertTo-Json 
    }
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
}

function ConfirmResize-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    $body = @{"confirmResize" =  $null } | convertTo-Json 
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
    
}

function RevertResize-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    $body = @{"revertResize" =  $null } | convertTo-Json 
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
    
}

function Rescue-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    $body = @{"rescue" =  "none" } | convertTo-Json 
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
    return $catalog.adminPass
}

function Unrescue-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    $body = @{"unrescue" =  $null } | convertTo-Json 
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
}

function CreateImage-RSNextGenServer(){
 param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$ImageName,
        [Parameter()]$Metadata
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$serverID/action"
    $authToken = @{"X-Auth-Token"=$APIToken}
   
    if ($Metadata.count -gt 0) { 
        $body = @{"createImage" =  @{"name" = "$ImageName"; "metaData" = $metadata}} | convertTo-Json 
    } else {
        $body = @{"createImage" =  @{"name" = "$ImageName"}} | convertTo-Json 
    }
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
}

function Get-RSNextGenServerMetadata(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$ServerID/metadata"

    $authToken = @{"X-Auth-Token"=$APIToken}
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method Get -Headers $authToken -ContentType application/json
    return $catalog.metadata
}

function Set-RSNextGenServerMetadata(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$Metadata
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$ServerID/metadata"

    $authToken = @{"X-Auth-Token"=$APIToken}
    $body = @{"metadata" =  $metadata} | convertTo-Json 
    
    $catalog = Invoke-RestMethod -Uri ($uri) -Method PUT -Body $body -Headers $authToken -ContentType application/json
    return $catalog.meta 
}

function Update-RSNextGenServerMetadata(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$Metadata
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$ServerID/metadata"

    $authToken = @{"X-Auth-Token"=$APIToken}
    $body = @{"metadata" =  $metadata} | convertTo-Json 
    
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
    return $catalog.meta 
}

function Get-RSNextGenServerMetadataItem(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$MetaKey
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$ServerID/metadata/$MetaKey"

    $authToken = @{"X-Auth-Token"=$APIToken}
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method Get -Headers $authToken -ContentType application/json
    return $catalog.meta
}

function Set-RSNextGenServerMetadataItem(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$MetaKey,
        [Parameter(Mandatory=$True,Position=4)]$MetaValue
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$ServerID/metadata/$MetaKey"

    $authToken = @{"X-Auth-Token"=$APIToken}
    $body = @{"meta" =  @{"$metaKey" = "$MetaValue"}} | convertTo-Json 
    

    $catalog = Invoke-RestMethod -Uri ($uri) -Method PUT -Body $body -Headers $authToken -ContentType application/json
    return $catalog.meta 
}

function Delete-RSNextGenServerMetadataItem(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ServerID,
        [Parameter(Mandatory=$True,Position=4)]$MetaKey
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/servers/$ServerID/metadata/$MetaKey"

    $authToken = @{"X-Auth-Token"=$APIToken}
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method DELETE -Headers $authToken -ContentType application/json
}

function Get-RSFlavor(){
 param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,Position=3,ParameterSetName='RSFlavorDetail')]$FlavorID,
        [Parameter(ParameterSetName='RSFlavorSearch')][switch]$DetailedList,
        [Parameter(ParameterSetName='RSFlavorSearch')]$MinDisk,
        [Parameter(ParameterSetName='RSFlavorSearch')]$MinRam,
        [Parameter(ParameterSetName='RSFlavorSearch')]$Marker,
        [Parameter(ParameterSetName='RSFlavorSearch')]$Limit
    ) 

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/flavors"
    $authToken = @{"X-Auth-Token"=$APIToken}

    if ($PsCmdlet.ParameterSetName -eq "RSFlavorDetail"){
        $uri = $uri + "/$FlavorId"
        $catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $authToken -ContentType application/json
        return $catalog.flavor 
    } else {

        $params= @()
        if ($detailedList.IsPresent) { $uri = $uri+"/detail" }
        if ($MinDisk -ne $null) { $params += "minDisk=$MinDisk" }
        if ($minRam -ne $null) { $params += "minRam=$minRam" }
        if ($Marker -ne $null) { $params += "marker=$Marker" }
        if ($Limit -ne $null) { $params += "limit=$Limit" }
        $p = $params -join "&"
        if ($p -ne "") { $uri = $uri + "?$p" }

        $catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $authToken -ContentType application/json
        return $catalog.flavors
    }
}

function Get-RSImage(){
 param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,Position=3,ParameterSetName='RSImageDetail')]$ImageID,
        [Parameter(ParameterSetName='RSImageSearch')][switch]$DetailedList,
        [Parameter(ParameterSetName='RSImageSearch')]$Server,
        [Parameter(ParameterSetName='RSImageSearch')]$Name,
        [Parameter(ParameterSetName='RSImageSearch')]$Status,
        [Parameter(ParameterSetName='RSImageSearch')]$ChangeDate,
        [Parameter(ParameterSetName='RSImageSearch')]$Marker,
        [Parameter(ParameterSetName='RSImageSearch')]$Limit,
        [Parameter(ParameterSetName='RSImageSearch')]$Type
    )
    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/images"
    $authToken = @{"X-Auth-Token"=$APIToken}

    if ($PsCmdlet.ParameterSetName -eq "RSImageDetail"){
        $uri = $uri + "/$ImageId"
        $catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $authToken -ContentType application/json
        return $catalog.image
    } else {

        $params= @()
        if ($detailedList.IsPresent) { $uri = $uri+"/detail" }
        if ($Server -ne $null) { $params += "server=$server" }
        if ($Name -ne $null) { $params += "name=$Name" }
        if ($Status -ne $null) { $params += "status=$Status" }
        if ($ChangeDate -ne $null) { $params += "changes-since=$ChangeDate" }
        if ($Marker -ne $null) { $params += "marker=$Marker" }
        if ($Limit -ne $null) { $params += "limit=$Limit" }
        if ($type -ne $null) { $params += "type=$type" }
        if ($ImageScheduled -ne $null) { $params += "RAX-SI:image_schedule=$ImageScheduled" }
        $p = $params -join "&"
        if ($p -ne "") { $uri = $uri + "?$p" }

        $catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $authToken -ContentType application/json
        return $catalog.images
    } 
}

function Delete-RSImage(){
 param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ImageID
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/images/$ImageID"

    $authToken = @{"X-Auth-Token"=$APIToken}
    
    $catalog = Invoke-RestMethod -Uri ($uri) -Method DELETE -Headers $authToken -ContentType application/json
    
}

function Get-RSImageMetadata(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ImageID
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/images/$ImageID/metadata"

    $authToken = @{"X-Auth-Token"=$APIToken}
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method Get -Headers $authToken -ContentType application/json
    return $catalog.metadata
}

function Set-RSImageMetadata(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ImageID,
        [Parameter(Mandatory=$True,Position=4)]$Metadata
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/images/$ImageID/metadata"

    $authToken = @{"X-Auth-Token"=$APIToken}
    $body = @{"metadata" =  $metadata} | convertTo-Json 
    
    $catalog = Invoke-RestMethod -Uri ($uri) -Method PUT -Body $body -Headers $authToken -ContentType application/json
    return $catalog.metadata 
}

function Update-RSImageMetadata(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ImageID,
        [Parameter(Mandatory=$True,Position=4)]$Metadata
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/images/$ImageID/metadata"

    $authToken = @{"X-Auth-Token"=$APIToken}
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Headers $authToken -ContentType application/json
    return $catalog.metadata
}

function Get-RSImageMetadataItem(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ImageID,
        [Parameter(Mandatory=$True,Position=4)]$MetaKey
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/images/$ImageID/metadata/$MetaKey"

    $authToken = @{"X-Auth-Token"=$APIToken}
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method Get -Headers $authToken -ContentType application/json
    return $catalog.meta
}

function Set-RSImageMetadataItem(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ImageID,
        [Parameter(Mandatory=$True,Position=4)]$MetaKey,
        [Parameter(Mandatory=$True,Position=4)]$MetaValue
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/images/$ImageID/metadata/$MetaKey"

    $authToken = @{"X-Auth-Token"=$APIToken}
    $body = @{"meta" =  @{"$metaKey" = "$MetaValue"}} | convertTo-Json 
    
    $catalog = Invoke-RestMethod -Uri ($uri) -Method PUT -Body $body -Headers $authToken -ContentType application/json
    return $catalog.meta 
}

function Delete-RSImageMetadataItem(){
param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$ImageID,
        [Parameter(Mandatory=$True,Position=4)]$MetaKey
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/images/$ImageID/metadata/$MetaKey"

    $authToken = @{"X-Auth-Token"=$APIToken}
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method DELETE -Headers $authToken -ContentType application/json
}

function Get-RSKeyPair(){
    param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/os-keypairs"
    $authToken = @{"X-Auth-Token"=$APIToken}

    $catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $authToken -ContentType application/json
    return $catalog.keypairs 
}

function New-RSKeyPair(){
    param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=2)]$KeyName,
        [Parameter()]$PublicKey
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/os-keypairs"
    $authToken = @{"X-Auth-Token"=$APIToken}
    if ($PublicKey -ne $null) { 
        $body = @{"keypair" =  @{"name" = "$keyName"; "public_key" = "$PublicKey"}} | convertTo-Json 
    } else {
        $body = @{"keypair" =  @{"name" = "$keyName"}} | convertTo-Json 
    }

    $catalog = Invoke-RestMethod -Uri ($uri) -Method POST -Body $body -Headers $authToken -ContentType application/json
    return $catalog.keypair 
}

function Delete-RSKeyPair(){
 param( 
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DDI,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipelinebyPropertyName=$True)]$DC, 
        [Parameter(Mandatory=$True,Position=3)]$KeyName
    )

    $uri = "https://$DC.servers.api.rackspacecloud.com/v2/$DDI/os-keypairs/$KeyName"

    $authToken = @{"X-Auth-Token"=$APIToken}
  
    $catalog = Invoke-RestMethod -Uri ($uri) -Method DELETE -Headers $authToken -ContentType application/json
}