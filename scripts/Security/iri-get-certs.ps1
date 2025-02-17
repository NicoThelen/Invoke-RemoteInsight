<#
.SYNOPSIS
    Lists all certificates on the system
.DESCRIPTION
    Reads all certificates from all existing scopes from the cert directory and lists them.
    The following details are provided:
    - StoreName
    - StoreScope
    - Thumbprint
    - Subject
    - Issuer
    - NotBefore
    - NotAfter
    - SerialNumber
    - HasPrivateKey
    - SignatureAlgorithm
    - FriendlyName
    - Archived
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-certs
.Notes
    Author: Nico Thelen
#>

Push-Location Cert:     # Push current directory to Cert:

try {
    $scopes = Get-ChildItem | ForEach-Object {$_.Location}              # Get all scopes (typically CurrentUser and LocalMachine)

    $cert_details = New-Object System.Collections.Generic.List[Object]   # Initialize an array to store results

    # Loop through each store location
    foreach ($scope in $scopes) {
        
        $stores = Get-ChildItem -Path "Cert:\$scope"                    # Get all stores in the current location

        # Loop through each store
        foreach ($store in $stores) {
            
            $store_name = $store.PSChildName                            # Create specific cert store object 
            $cert_store = New-Object System.Security.Cryptography.X509Certificates.X509Store($store_name, $scope)

            try {
                $cert_store.Open("ReadOnly")                            # Open the store to access certificates
                
                # Enumerate all certificates in the store
                foreach ($cert in $cert_store.Certificates) {
                    $cert_details.Add([PSCustomObject]@{
                        StoreName         = $store_name
                        StoreScope        = $scope
                        Thumbprint        = $cert.Thumbprint
                        Subject           = $cert.Subject
                        Issuer            = $cert.Issuer
                        NotBefore         = $cert.NotBefore
                        NotAfter          = $cert.NotAfter
                        SerialNumber      = $cert.SerialNumber
                        HasPrivateKey     = $cert.HasPrivateKey
                        SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
                        FriendlyName      = $cert.FriendlyName
                        Archived          = $cert.Archived
                    })
                }
            } catch {
                
            } finally {
                $cert_store.Close()                                     # Close the store
            }
        }
    }
} catch { 
    
} finally {
    Pop-Location                                            # Reset current directory location
}


Write-Output $cert_details