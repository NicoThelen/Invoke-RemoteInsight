<#
.SYNOPSIS
    All installed Products
.DESCRIPTION
    Provides an overview of all installed products. 
    Depending on the type of product or installation, different information is collected.
    Independent information for all types:
    - Name
    - Summary/Description
    - Vendor/Publisher
    - Version
    - ProviderName
    - Installed

    Information for products installed by windows installer:
    - InstallDate
    - InstallDate2
    - InstallSource
    - PackageName
    - URLInfoAbout
    - URLUpdateInfo
    
    Information for products NOT installed by windows installer:
    - UninstallString
.EXAMPLE
    Invoke-RemoteInsight@*TargetSystem*>: iri-get-products
.Notes
    Author: Nico Thelen
#>

$product_results = @()

## All products installed by windows installer ###
$products_win_installer = Get-WmiObject Win32_Product

foreach ($wmi_product in $products_win_installer) { 
    $product_results += [PSCustomObject]@{      
        Name = $wmi_product.Name 
        Summary = $wmi_product.Description
        Vendor = $wmi_product.Vendor 
        Version = $wmi_product.Version
        ProviderName = "msi"
        Installed = switch ($wmi_product.InstallState) {
            5 {"Installed"}
            2 {"Absent"}
            1 {"Advertised"}
            -1 {"Unknown Package"}
            -2 {"Invalid Argument"}
            -6 {"Bad Configuration"}
        }
        InstallDate = $wmi_product.InstallDate
        InstallDate2 = $wmi_product.InstallDate2
        InstallSource = $wmi_product.InstallSource
        PackageName = $wmi_product.PackageName
        URLInfoAbout = $wmi_product.URLInfoAbout
        URLUpdateInfo = $wmi_product.URLUpdateInfo
        UninstallString = "N/A - Information only available for non-MSI products"
    }
}

###################################################

<#
Two different methods are used to query the installed products in order to maximize the information content
All products installed by windows installer via the top method as this provides the maximum information
In order to display all installed products in addition to these above, the lower method must query all remaining products, with partially differing information content
#>

### All other products installed ###
$products_except_win_installer = Get-Package | Where-Object ProviderName -ne msi   # Get all products except the ones provided by msi

foreach ($product in $products_except_win_installer) {
    foreach($metadata in $product.metadata.Keys) {
        $vendor = $product.metadata["Publisher"]
        $uninstallString = $product.metadata["UninstallString"]
    }
    $product_results += [PSCustomObject]@{     
        Name = $product.Name 
        Summary = $product.Summary
        Vendor = $vendor -join ""
        Version = $product.Version
        ProviderName = $product.ProviderName
        Installed = $product.Status
        InstallDate = "N/A - Information only available for MSI products"
        InstallDate2 = "N/A - Information only available for MSI products"
        InstallSource = "N/A - Information only available for MSI products"
        PackageName = "N/A - Information only available for MSI products"
        URLInfoAbout = "N/A - Information only available for MSI products"
        URLUpdateInfo = "N/A - Information only available for MSI products"
        UninstallString = $uninstallString -join ""
    }
}

Write-Output $product_results