<#
.SYNOPSIS
Autenticates to the Rackspace Cloud API.
.PARAMETER username
The username for the Rackspace Cloud account.
.PARAMETER APIkey
The current API account for the username.

.EXAMPLE
# Shows a basic API Authentication
$auth = Get-RSAuth –username <user> -APIKey <APIKey>
#>

<#function Get-RSAuthOld(){
    param(
        [Parameter(Mandatory=$True,ParameterSetName='UsernameAuth')][string]$Username,
        [Parameter(Mandatory=$True,ParameterSetName='UsernameAuth')][string]$APIKey,
        
        [Parameter(Mandatory=$True,ParameterSetName='TokenAuth')][string]$DDI,
        [Parameter(Mandatory=$True,ParameterSetName='TokenAuth')][string]$APIToken
        
    )

    $uri = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    if ($PSCmdlet.ParameterSetName -eq 'UsernameAuth') {
        $body = @{"auth" = @{"RAX-KSKEY:apiKeyCredentials" =  @{"username" = "$UserName"; "apiKey" = "$APIKey"}}} | convertTo-Json
    } elseif ($PSCmdlet.ParameterSetName -eq 'TokenAuth') {
        $body = @{"auth" = @{"tenantId"="$DDI";"token" =  @{"id" = "$APIToken"}}} | convertTo-Json
    }
    write-debug "Calling: `n`nURI:$uri `nHeader:$($header | Format-List | Out-String) `nRequest Body:$body"
    $catalog = Invoke-RestMethod -Uri $uri -Method POST -Body $body -ContentType application/json

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

    
    $authProps = @{
        "Type"="cloudIdentity";
        "Username"="$username";
        "apiKey"="$apiKey";
        "DDI"="$($catalog.access.token.tenant.id)";
        "APIToken"="$($catalog.access.token.id)";
        "catalog"=$serviceCatalog;
        "TokenExpiry"=[datetime]$catalog.access.token.expires;
        "test" = 4
    }
    if ($debug) { 
        $authProps.add("json","$($catalog | ConvertTo-Json -depth 10)")
        $authProps.add("cat",$catalog)
    }

    $auth = New-Object -TypeName PSObject –Prop $authProps

    $auth | add-member scriptmethod tostring { $this.APIToken } -force
    $auth | add-member scriptmethod increment { $this.test++ } -force
    $auth | add-member scriptmethod decrement { $this.test-- } -force
    $auth | add-member scriptmethod getRegions {param([Parameter(Mandatory=$True)][string]$serviceType)  $this.catalog[$serviceType].keys } -force
    $auth
} #>

<#
.SYNOPSIS
Autenticates to the Rackspace Cloud API.
.PARAMETER username
The username for the Rackspace Cloud account.
.PARAMETER APIkey
The current API account for the username.

.EXAMPLE
# Shows a basic API Authentication
$auth = Get-RSAuth –username <user> -APIKey <APIKey>
#>
function Get-RSAuth(){
    param(
        [Parameter(Mandatory=$True,ParameterSetName='UsernameAuth')][string]$Username,
        [Parameter(Mandatory=$True,ParameterSetName='UsernameAuth')][string]$APIKey
        
        #[Parameter(Mandatory=$True,ParameterSetName='TokenAuth')][string]$DDI,
        #[Parameter(Mandatory=$True,ParameterSetName='TokenAuth')][string]$APIToken
        
    )
    write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $type = "cloudIdentity"
    $uri = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    if ($PSCmdlet.ParameterSetName -eq 'UsernameAuth') {
        $body = @{"auth" = @{"RAX-KSKEY:apiKeyCredentials" =  @{"username" = "$UserName"; "apiKey" = "$APIKey"}}} | ConvertTo-Json -Compress
    } elseif ($PSCmdlet.ParameterSetName -eq 'TokenAuth') {
        $body = @{"auth" = @{"tenantId"="$DDI";"token" =  @{"id" = "$APIToken"}}} | ConvertTo-Json -Compress
    }

    $catalog = RS_API_Call -method "POST" -uri $uri -body $body

    $catalog | Add-Member -MemberType NoteProperty -Name Username -Value $Username -Force
    $catalog | Add-Member -MemberType NoteProperty -Name APIKey -Value $APIKey  -Force
    $catalog | Add-Member -MemberType NoteProperty -Name type -Value $type -Force

    $catalog | Add-Member -MemberType scriptmethod -Name DDI -Value { $this.access.token.tenant.id } -Force
    $catalog | Add-Member -MemberType scriptmethod -Name APIToken -Value { $this.access.token.id } -Force
    $catalog | add-member -MemberType scriptmethod -name isExpired -value { (Get-Date) -gt $this.access.token.expires } -force
    $catalog | add-member -MemberType scriptmethod -name getRegions -value { 
        param([Parameter(Mandatory=$True)][string]$serviceType) 
        ($this.access.serviceCatalog | where-object -property name -eq $serviceType).endpoints.region 
    } -force

    $catalog | add-member -MemberType scriptmethod -name getEndpoint -value { 
        param([Parameter(Mandatory=$True)][string]$serviceType,[string]$region) 
        if (($this.access.serviceCatalog | where-object -property name -eq $type).endpoints[0].region -eq $null) {
            ($this.access.serviceCatalog | where-object -property name -eq $type).endpoints[0].publicURL
        } else {
            (($this.access.serviceCatalog | where-object -property name -eq $type).endpoints | where-object -property region -eq $region).PublicURL 
        }
    } -force
    $catalog | add-member -membertype scriptmethod -name reAuthenticate -value { 
        if ( $this.username -ne $null) { $this.access = (Get-RSAuth -username $this.username -apiKey $this.apiKey).access;$this.APIToken = $this.access.token.id }
    } -force

    $catalog

} 

<#
.SYNOPSIS
Autenticates to the Rackspace Cloud API.
.PARAMETER username
The username for the Rackspace Cloud account.
.PARAMETER APIkey
The current API account for the username.

.EXAMPLE
# Shows a basic API Authentication
$auth = Get-RSAuth –username <user> -APIKey <APIKey>
#>
function Get-RSNextGenServer(){
   #[CmdletBinding(DefaultParametersetName="RSServerSearch")] 
    param( 
        [Parameter(Mandatory=$True,ParameterSetName='NoAuth')][string]$DDI,
        [Parameter(Mandatory=$True,ParameterSetName='NoAuth')][string]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ParameterSetName='Auth')][object]$inputObject,
        [Parameter()][string[]]$DC, 
        [Parameter()][string[]]$ServerID,
        [Parameter()][string[]]$Image,
        [Parameter()][string[]]$Flavor,
        [Parameter()][string]$Name,
        [Parameter()][string[]]$Status
    ) 
    BEGIN {
        $type = "cloudServersOpenStack"
        
    }
    PROCESS {
        write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
        if ($PSCmdlet.ParameterSetName -eq 'NoAuth') {
            $inputObject += Get-RSAuth -DDI $DDI -APIToken $APIToken
        }
        Foreach ($auth in ( $inputObject | where-object -property type -eq "cloudIdentity" ) ) {
            $datacenters = $auth.getRegions($type)
            if ($dc.count -eq 0 ) { $DClist  = $datacenters} else {  $DClist  = $dc }
            foreach ($datacenter in $DClist) {
                write-debug "Querying DC $datacenter"
                if ($datacenters -contains $datacenter) {
                    $uri = $auth.getEndpoint($type,$datacenter)
                    if ($serverID.count -eq 1) {
                        $uri = $uri + "/servers/$($serverID[0])"
                        $apiResult = "server" 
                    } else {
                        $uri = $uri + "/servers/detail" 
                        $apiResult="servers"
                    }
                    $header = @{"X-Auth-Token"="$($auth.access.token.id)"} 

                    $continue = $true
                    try {
                        if ($auth.isExpired()) {$auth.reAuthenticate()}
                        $catalog = RS_API_Call -method "GET" -uri $uri -Header $header 
                        #$catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $header -ContentType application/json
                    } catch {
                        Write-debug "API Call Failed $_"
                        write-debug ($_.Exception.Response.StatusCode.value__| out-string )
                        Switch ($_.Exception.Response.StatusCode.value__){
                            404 { Write-Debug "Instance Not Found $uri `n $_ .  No need to worry."}
                            #401 { Write-Error "Unauthorized $uri `n $_"}
                            #400 { Write-Error "Bad Request $uri `n $_"}
                            #403 { Write-Error Forbidden $_}
                            #405 { Write-Error Methid Not Allowed $_}
                            #413 { Write-Error Over API Limit $_}
                            #503 { Write-Error Service Unavailable $_}
                            #500 { Write-Error Unknow Error $_}
                            default { throw $_ }
                        }
                        $continue = $false
                        
                    }
                    if ($continue) {
                        $result = $catalog.($apiResult) 
                        if ($name -ne $null) {$result = $result | where-object -property name -match "$Name"}
                        if ($image.count -ne 0) {$result = $result | where-object -property image.id -in $image}
                        if ($flavor.count -ne 0) {$result = $result | where-object -property flavor.id -in $flavor}
                        if ($status.count -ne 0) {$result = $result | where-object -property "OS-EXT-STS:vm_state" -match $status}
                        foreach ($server in $result) {
                            create_serverObject -server $server -Auth $auth -type $type                            
                        }
                    }   
                }
            }
        
            # do stuff here with $computer
        } 
    } 
    END {

    }   
}

function create_serverObject(){
    param( 
        [Parameter(Mandatory=$True)]$server,
        [Parameter(Mandatory=$True)]$Auth,
        [Parameter(Mandatory=$True)]$type
    ) 
    $obj = New-Object -TypeName PSObject

    $obj | Add-Member -MemberType NoteProperty -Name Auth -Value $auth -Force
    $obj | Add-Member -MemberType NoteProperty -Name server -Value $server -Force
    $obj | Add-Member -MemberType NoteProperty -Name type -Value $type -Force

    $obj | add-member -MemberType scriptmethod -name getDC -value { (($this.auth.access.serviceCatalog | where name -eq $this.type).endpoints | where-object {($this.server.links | where-object -Property rel -eq "self").href -match $_.publicURL}).region } -force
    $obj | add-member -MemberType scriptmethod -name refresh -value { $this.server = ($this.auth | Get-RSNextGenServer -serverID $this.server.id -dc $this.getDC() ).server}  -force
    $obj | add-member -MemberType scriptmethod -name update -value { Update_RSNextGenServer -server $this; $this.refresh() } -force
    $obj | add-member -MemberType scriptmethod -name delete -value { Delete_RSNextGenServer -server $this } -force
    $obj | add-member -MemberType scriptmethod -name changePassword -value { param([string]$password); ChangeAdminPass_RSNextGenServer -server $this -AdminPass $password } -force
    $obj | add-member -MemberType scriptmethod -name reboot -value { Reboot_RSNextGenServer -server $this } -force
    $obj | add-member -MemberType scriptmethod -name hardReboot -value { Reboot_RSNextGenServer -server $this -HardReboot } -force
    $obj | add-member -MemberType scriptmethod -name rebuild -value { } -force
    $obj | add-member -MemberType scriptmethod -name resize -value {  } -force
    $obj | add-member -MemberType scriptmethod -name confirmResize -value {  } -force
    $obj | add-member -MemberType scriptmethod -name revertResize -value {  } -force
    $obj | add-member -MemberType scriptmethod -name rescue -value {  } -force
    $obj | add-member -MemberType scriptmethod -name unrescue -value {  } -force
    $obj | add-member -MemberType scriptmethod -name createImage -value {  } -force
    $obj | add-member -MemberType scriptmethod -name setMetaData -value { 
        param([string]$key,[string]$value) 
        Switch ($this.server.metadata.GetType().name){
            "PSCustomObject" {$this.server.metadata | Add-Member -MemberType NoteProperty -Name $key -Value $value -Force}
            "Hashtable"      {$this.server.metadata.add($key,$value)}
        }
    } -force
    $obj | add-member -MemberType scriptmethod -name deleteMetadata -value { 
        param([string]$key) 
        Switch ($this.server.metadata.GetType().name){
            "PSCustomObject" {$this.server.metadata.PSObject.Properties.Remove($key) }
            "Hashtable"      {$this.server.metadata.remove($key)}
        }
    } -force
    
    $obj
}

function Update_RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)]$Server
    )
    write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = ($server.server.links | where-object -Property rel -eq "self").href
    $header = @{"X-Auth-Token"=$server.auth.access.token.ID}
    $body = @{"server" =  @{"name"="$($server.server.name)";"AccessIPv4"="$($server.server.accessIPv4)";"AccessIPv6"="$($server.server.accessIPv6)"}} | ConvertTo-Json -Compress

    if ($auth.isExpired()) {$auth.reAuthenticate()}
    $catalog = RS_API_Call -method "PUT" -uri $uri -body $body -Header $header

    $uri = $uri + "/metadata"
    $body = @{"metadata" =  $server.server.metadata} | convertTo-Json  -Compress

    if ($auth.isExpired()) {$auth.reAuthenticate()}
    $catalog = RS_API_Call -method "PUT" -uri $uri -body $body -Header $header    
}

function Delete_RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)]$Server
    )
    write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = ($server.server.links | where-object -Property rel -eq "self").href
    $header = @{"X-Auth-Token"=$server.auth.access.token.ID}

    if ($auth.isExpired()) {$auth.reAuthenticate()}
    $catalog = RS_API_Call -method "DELETE" -uri $uri -Header $header
}

function New-RSNextGenServer(){
[CmdletBinding(DefaultParametersetName="AutoDisk")] 
param( 
        [Parameter(Mandatory=$True,ParameterSetName='NoAuth')][string]$DDI,
        [Parameter(Mandatory=$True,ParameterSetName='NoAuth')][string]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ParameterSetName='Auth')][object]$inputObject,
        [Parameter(Mandatory=$True)][string]$DC, 
        [Parameter(Mandatory=$True)][string]$Flavor,
        [Parameter(Mandatory=$True)][string]$Name,
        [Parameter(Mandatory=$True)][string]$Image,
        [Parameter()][ValidateSet("AUTO","MANUAL")][string]$diskConfig,
        [Parameter()]$Metadata, 
        [Parameter()]$Personality,
        [Parameter()][string[]]$Networks, 
        [Parameter()][string]$KeyPair 
    )
    BEGIN {
        $type = "cloudServersOpenStack"
        
    }
    PROCESS {
        write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
        if ($PSCmdlet.ParameterSetName -eq 'NoAuth') {
            $inputObject += Get-RSAuth -DDI $DDI -APIToken $APIToken
        }
        Foreach ($auth in ( $inputObject | where-object -property type -eq "cloudIdentity" ) ) {
            write-debug "Entering Loop"
            $datacenters = $auth.getRegions($type)
            if ($datacenters -contains $dc) {
                $uri = $auth.getEndpoint($type,$dc)+"/servers"
                $apiResult="server"
                $header = @{"X-Auth-Token"="$($auth.access.token.id)"} 
                $body = @{"server" =  @{"name" = "$Name";"imageRef" = "$image";"flavorRef" = "$Flavor"}}

                if ($diskConfig -ne "") { 
                    $body.server.add("config_drive", $true) 
                    $body.server.add("OS-DCF:diskConfig", "$diskConfig")
                }
                if ($Metadata.count -gt 0) { 
                    $body.server.add("metadata", $metaData) 
                }
               <# if ($personality.count -gt 0) { 
                    $body.server.add("personality", @()) 
                    foreach ($key in $Personality.keys){
                        
                       $body.server.personality += @(@{"path"="$key";"contents"=$($personality[$key])})
                    }
                    #$personality_array
                    #write-debug ($personality_array | out-string)
                    #$body.server.add("personality", $personality_array) 
                }#>
                if ($networks.count -gt 0) { 
                    $body.server.add("networks", $networks) 
                }
                if ($KeyPair -ne "") { 
                    $body.server.add("keypair", @{"key_name" = "$keyPair"})  
                }

                $body = $body | ConvertTo-Json  -Compress
                $continue = $true
                try {
                    if ($auth.isExpired()) {$auth.reAuthenticate()}
                    $catalog = RS_API_Call -method "POST" -uri $uri -body $body -Header $header
                } catch {
                    Write-debug "API Call Failed $_"
                    write-debug ($_.Exception.Response.StatusCode.value__| out-string )
                    Switch ($_.Exception.Response.StatusCode.value__){
                        404 { Write-Debug "Instance Not Found $uri `n $_ "}
                        401 { Write-Error "Unauthorized $uri `n $_"}
                        400 { Write-Error "Bad Request $uri `n $_"}
                        403 { Write-Error Forbidden $_}
                        405 { Write-Error Methid Not Allowed $_}
                        413 { Write-Error Over API Limit $_}
                        503 { Write-Error Service Unavailable $_}
                        500 { Write-Error Unknow Error $_}
                    }
                    $continue = $false
                }
                if ($continue) {
                    $result = $catalog.($apiResult) 
                    foreach ($server in $result) {
                        $auth | get-RSNextGenServer -serverid $server.id -dc $DC
                    }
                }
            }
        }
    }
}

function ChangeAdminPass_RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)]$Server,
        [Parameter(Mandatory=$True)][string]$AdminPass
    )
    write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = ($server.server.links | where-object -Property rel -eq "self").href + "/action"
    $header = @{"X-Auth-Token"=$server.auth.access.token.ID}
   
    $body = @{"changePassword" =  @{"adminPass" = "$AdminPass"}} | convertTo-Json  -Compress

    if ($auth.isExpired()) {$auth.reAuthenticate()}
    $catalog = RS_API_Call -method "POST" -uri $uri -body $body -Header $header
}

function Reboot_RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)]$Server,
        [Parameter()][switch]$HardReboot
    )
    write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = ($server.server.links | where-object -Property rel -eq "self").href + "/action"
    $header = @{"X-Auth-Token"=$server.auth.access.token.ID}
   
    if ($HardReboot.IsPresent) { 
        $body = @{"reboot" =  @{"type" = "HARD"}} | convertTo-Json  -Compress
    } else {
        $body = @{"reboot" =  @{"type" = "SOFT"}} | convertTo-Json  -Compress
    }

    if ($auth.isExpired()) {$auth.reAuthenticate()}
    $catalog = RS_API_Call -method "POST" -uri $uri -body $body -Header $header
}

function Rebuild_RSNextGenServer(){
[CmdletBinding(DefaultParametersetName="AutoDisk")] 
param( 
        [Parameter(Mandatory=$True)]$Server,
        [Parameter()]$Image,
        [Parameter()]$Name,
        [Parameter()][ValidateSet("AUTO","MANUAL")][string]$diskConfig,
        [Parameter()]$Metadata, 
        [Parameter()]$Personality,
        [Parameter()]$AdminPass 
    )
    write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = ($server.server.links | where-object -Property rel -eq "self").href + "/action"
    $header = @{"X-Auth-Token"=$server.auth.access.token.ID}

    $body = @{"rebuild" =  @{"imageRef" = "$image"}}
    if ($image -ne "") { 
        $body = @{"rebuild" =  @{"imageRef" = "$image"}}
    } else {
        $body = @{"rebuild" =  @{"imageRef" = "$($server.server.image.id)"}}
    }
    if ($Name -ne "") { 
        $body.rebuild.add("name",$Name)
    }
    if ($diskConfig -ne "") { 
        $body.server.add("config_drive", $true) 
        $body.server.add("OS-DCF:diskConfig", "$diskConfig")
    }
    if ($Metadata.count -gt 0) { 
        $body.rebuild.add("metadata", $metaData) 
    }
    <#
    if ($personality.count -gt 0) { 
        $body.rebuild.add("metadata", $metaData) 
    }
    #>
    if ($adminPass -ne $null) { 
        $body.rebuild.add("adminPass", $AdminPass)  
    }

    $body = $body | ConvertTo-Json  -Compress
    
    if ($auth.isExpired()) {$auth.reAuthenticate()}
    $catalog = RS_API_Call -method "POST" -uri $uri -body $body -Header $header
}



function Resize_RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)]$Server,
        [Parameter(Mandatory=$True)]$FlavorID,
        [Parameter()][ValidateSet("AUTO","MANUAL")][string]$diskConfig
    )
    write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = ($server.server.links | where-object -Property rel -eq "self").href + "/action"
    $header = @{"X-Auth-Token"=$server.auth.access.token.ID}

    if ($diskConfig -ne "") { 
        $body = @{"resize" =  @{"flavorRef" = "$flavorID";"OS-DCF:diskConfig" = "$diskConfig";"config_drive"="$true"}} | convertTo-Json   -Compress
    } else {
        $body = @{"resize" =  @{"flavorRef" = "$flavorID"}} | convertTo-Json   -Compress
    }

    if ($auth.isExpired()) {$auth.reAuthenticate()}
    $catalog = RS_API_Call -method "POST" -uri $uri -body $body -Header $header
}


<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

function Get-RSFlavor(){
param( 
        [Parameter(Mandatory=$True,ParameterSetName='NoAuth')][string]$DDI,
        [Parameter(Mandatory=$True,ParameterSetName='NoAuth')][string]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ParameterSetName='Auth')][object]$inputObject,
        [Parameter()][string[]]$DC, 
        [Parameter()][string[]]$FlavorID,
        [Parameter()][int]$MinDisk=0,
        [Parameter()][int]$MinDataDisk=0,
        [Parameter()][int]$MinRam=0,
        [Parameter()][int]$MinSwap=0,
        [Parameter()][int]$MinCPU=0
    ) 
    BEGIN {
        $type = "cloudServersOpenStack"
        
    }
    PROCESS {
        write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        if ($PSCmdlet.ParameterSetName -eq 'NoAuth') {
            $inputObject += Get-RSAuth -DDI $DDI -APIToken $APIToken
        }
        Foreach ($auth in ( $inputObject | where-object -property type -eq "cloudIdentity" ) ) {
            write-debug "Entering Loop"
            $datacenters = $auth.getRegions($type)
            write-debug ($datacenters | out-string)
            if ($dc.count -eq 0 ) { $DClist  = $datacenters} else {  $DClist  = $dc }
            foreach ($datacenter in $DClist) {
                write-debug "Querying DC $datacenter"
                if ($datacenters -contains $datacenter) {
                    $uri = $auth.getEndpoint($type,$datacenter)
                    if ($flavorID.count -eq 1) {
                        $uri = $uri + "/flavors/$($flavorID[0])"
                        $apiResult = "flavor" 
                    } else {
                        $uri = $uri + "/flavors/detail" 
                        $apiResult="flavors"
                    }
                    $header = @{"X-Auth-Token"="$($auth.access.token.id)"} 

                    $continue = $true
                    try {
                        if ($auth.isExpired()) {$auth.reAuthenticate()}
                        $catalog = RS_API_Call -method "GET" -uri $uri -Header $header
                        #write-debug "API Call Information: `n`nURI:$uri `nHeader:$($header | Format-List | Out-String) `nRequest Body:$body"
                        #if ($auth.isExpired()) {$auth.reAuthenticate()}
                        #$catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $header -ContentType application/json
                    } catch {
                        Write-debug "API Call Failed $_"
                        write-debug ($_.Exception.Response.StatusCode.value__| out-string )
                        Switch ($_.Exception.Response.StatusCode.value__){
                            404 { Write-Debug "Instance Not Found $uri `n $_ "}
                            401 { Write-Error "Unauthorized $uri `n $_"}
                            400 { Write-Error "Bad Request $uri `n $_"}
                            403 { Write-Error Forbidden $_}
                            405 { Write-Error Methid Not Allowed $_}
                            413 { Write-Error Over API Limit $_}
                            503 { Write-Error Service Unavailable $_}
                            500 { Write-Error Unknow Error $_}
                        }
                        $continue = $false
                    }
                    if ($continue) {
                        $result = $catalog.($apiResult) 
                        if ($MinDisk -gt 0) {$result = $result | where-object -property disk -ge "$MinDisk"}
                        if ($MinDataDisk -gt 0) {$result = $result | where-object -property "OS-FLV-EXT-DATA:ephemeral" -ge "$MinDataDisk"}
                        if ($MinSwap -gt 0) {$result = $result | where-object -property swap -ge "$MinSwap"}
                        if ($MinRam -gt 0) {$result = $result | where-object -property ram -ge "$MinRam"}
                        if ($MinRam -gt 0) {$result = $result | where-object -property vcpus -ge "$MinCPU"}
                        if ($FlavorID.count -gt 1) {$result = $result | where-object -property id -in $FlavorID}
                       
                        foreach ($flavor in $result) {
                            $flavor
                            #create_serverObject -server $server -Auth $auth -type $type                            
                        }
                    }   
                }
            }
        
            # do stuff here with $computer
        } 
    } 
    END {

    }   
}


function Get-RSImage(){
param( 
        [Parameter(Mandatory=$True,ParameterSetName='NoAuth')][string]$DDI,
        [Parameter(Mandatory=$True,ParameterSetName='NoAuth')][string]$APIToken,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ParameterSetName='Auth')][object]$inputObject,
        [Parameter()][string[]]$DC, 
        [Parameter()][string[]]$ImageID,
        [Parameter()][string[]]$ServerID,
        [Parameter()][string[]]$Status,
        [Parameter()][DateTime]$ChangeDate
    ) 
    BEGIN {
        $type = "cloudImages"
        
    }
    PROCESS {
        write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        if ($PSCmdlet.ParameterSetName -eq 'NoAuth') {
            $inputObject += Get-RSAuth -DDI $DDI -APIToken $APIToken
        }
        Foreach ($auth in ( $inputObject | where-object -property type -eq "cloudIdentity" ) ) {
            write-debug "Entering Loop"
            $datacenters = $auth.getRegions($type)
            write-debug ($datacenters | out-string)
            if ($dc.count -eq 0 ) { $DClist  = $datacenters} else {  $DClist  = $dc }
            foreach ($datacenter in $DClist) {
                write-debug "Querying DC $datacenter"
                if ($datacenters -contains $datacenter) {
                    $uri = $auth.getEndpoint($type,$datacenter)
                    if ($imageID.count -eq 1) {
                        $uri = $uri + "/images/$($imageID[0])"
                        $apiResult = "image" 
                    } else {
                        $uri = $uri + "/images" 
                        $apiResult="images"
                    }
                    $header = @{"X-Auth-Token"="$($auth.access.token.id)"} 

                    $continue = $true
                    try {
                        if ($auth.isExpired()) {$auth.reAuthenticate()}
                        $catalog = RS_API_Call -method "GET" -uri $uri -Header $header

                        #write-debug "API Call Information: `n`nURI:$uri `nHeader:$($header | Format-List | Out-String) `nRequest Body:$body"
                        #if ($auth.isExpired()) {$auth.reAuthenticate()}
                        #$catalog = Invoke-RestMethod -Uri ($uri) -Method GET -Headers $header -ContentType application/json
                    } catch {
                        Write-debug "API Call Failed $_"
                        write-debug ($_.Exception.Response.StatusCode.value__| out-string )
                        Switch ($_.Exception.Response.StatusCode.value__){
                            404 { Write-Debug "Instance Not Found $uri `n $_ "}
                            401 { Write-Error "Unauthorized $uri `n $_"}
                            400 { Write-Error "Bad Request $uri `n $_"}
                            403 { Write-Error Forbidden $_}
                            405 { Write-Error Methid Not Allowed $_}
                            413 { Write-Error Over API Limit $_}
                            503 { Write-Error Service Unavailable $_}
                            500 { Write-Error Unknow Error $_}
                        }
                        $continue = $false
                    }
                    if ($continue) {
                        $result = $catalog.($apiResult) 
                        if ($MinDisk -gt 0) {$result = $result | where-object -property disk -ge "$MinDisk"}
                        if ($MinDataDisk -gt 0) {$result = $result | where-object -property "OS-FLV-EXT-DATA:ephemeral" -ge "$MinDataDisk"}
                        if ($MinSwap -gt 0) {$result = $result | where-object -property swap -ge "$MinSwap"}
                        if ($MinRam -gt 0) {$result = $result | where-object -property ram -ge "$MinRam"}
                        if ($MinRam -gt 0) {$result = $result | where-object -property vcpus -ge "$MinCPU"}
                        if ($FlavorID.count -gt 1) {$result = $result | where-object -property id -in $ImageID}
                        #if ($ServerID.count -ne 0) {$result = $result | where-object -property id -in $ImageID}
                        if ($status.count -ne 0) {$result = $result | where-object -property status -in $status}
                        if ($changeDate -gt 0) {$result = $result | where-object { [dateTime]$_.updated_at -ge $changeDate} }
                       
                        foreach ($image in $result) {
                            
                            create_imageObject -image $image -Auth $auth -type $type -dc $datacenter                           
                        }
                    }   
                }
            }
        
            # do stuff here with $computer
        } 
    } 
    END {

    }   
}

function create_imageObject(){
    param( 
        [Parameter(Mandatory=$True)]$image,
        [Parameter(Mandatory=$True)]$Auth,
        [Parameter(Mandatory=$True)]$type,
        [Parameter(Mandatory=$True)]$dc
    ) 
    $obj = New-Object -TypeName PSObject

    $obj | Add-Member -MemberType NoteProperty -Name Auth -Value $auth -Force
    $obj | Add-Member -MemberType NoteProperty -Name image -Value $image -Force
    $obj | Add-Member -MemberType NoteProperty -Name type -Value $type -Force
    $obj | Add-Member -MemberType NoteProperty -Name dc -Value $dc -Force

    $obj | add-member -MemberType scriptmethod -name refresh -value { $this.server = ($this.auth | Get-RSImage -ImageID $this.image.id -dc $this.DC ).image}  -force

    <#$obj | add-member -MemberType scriptmethod -name update -value { Update_RSNextGenServer -server $this } -force
    $obj | add-member -MemberType scriptmethod -name delete -value { Delete_RSNextGenServer -server $this } -force
    $obj | add-member -MemberType scriptmethod -name changePassword -value { param($password); ChangeAdminPass_RSNextGenServer -server $this -AdminPass $password } -force
    $obj | add-member -MemberType scriptmethod -name softReboot -value { Reboot_RSNextGenServer -server $this } -force
    $obj | add-member -MemberType scriptmethod -name hardReboot -value { Reboot_RSNextGenServer -server $this -HardReboot } -force
    $obj | add-member -MemberType scriptmethod -name rebuild -value {  } -force
    $obj | add-member -MemberType scriptmethod -name resize -value {  } -force
    $obj | add-member -MemberType scriptmethod -name confirmResize -value {  } -force
    $obj | add-member -MemberType scriptmethod -name revertResize -value {  } -force
    $obj | add-member -MemberType scriptmethod -name rescue -value {  } -force
    $obj | add-member -MemberType scriptmethod -name unrescue -value {  } -force
    $obj | add-member -MemberType scriptmethod -name createImage -value {  } -force
    $obj | add-member -MemberType scriptmethod -name addMetaData -value {  } -force
    $obj | add-member -MemberType scriptmethod -name deleteMetadata -value {  } -force
    #>
    $obj | add-member -MemberType scriptmethod -name getDC -value { $this.dc } -force
    $obj
}

<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

<#
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
#>

function RS_API_Call(){
    param(
        [Parameter(Mandatory=$True)][string]$method,
        [Parameter(Mandatory=$True)][string]$uri,
        [Parameter()]$header,
        [Parameter()][string]$body        
    )    
    write-debug "Entering $($MyInvocation.MyCommand) Function.`nParameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $params = @{"Uri"=$uri;"Method"=$method;"ContentType"="application/json"}
    
    if ($body -ne "") { $params.add("Body",$body)} 
    if ($header -ne $null) { $params.add("Headers",$header)}
    write-debug "`n`nMETHOD:$method`nURI:$uri`nHEADER:$($header | Out-String)`nBODY:`n$body"  
    Invoke-RestMethod @params
}