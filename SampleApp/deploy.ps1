$endpoint = 'jomasf.westus.cloudapp.azure.com:19000'
$thumbprint = '<CertThumbprint>'

# Connect to the cluster using a client certificate.
Connect-ServiceFabricCluster -ConnectionEndpoint $endpoint `
          -KeepAliveIntervalInSec 10 `
          -X509Credential -ServerCertThumbprint $thumbprint `
          -FindType FindByThumbprint -FindValue $thumbprint `
          -StoreLocation CurrentUser -StoreName My

$AppPath = "$PSScriptRoot\SampleApp\pkg\Debug"

# Copy the application package to the cluster image store.
Copy-ServiceFabricApplicationPackage -ApplicationPackagePath $AppPath -ImageStoreConnectionString fabric:ImageStore -ApplicationPackagePathInImageStore SampleApp -ShowProgress

# Register the application type.
Register-ServiceFabricApplicationType -ApplicationPathInImageStore SampleApp

# Create the application instance.
New-ServiceFabricApplication -ApplicationName fabric:/SampleApp `
-ApplicationTypeName SampleAppType `
-ApplicationTypeVersion 1.0.0
