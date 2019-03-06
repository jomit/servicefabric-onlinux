# ------------------------------------------------------------
# Copyright (c) Microsoft Corporation.  All rights reserved.
# Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
# ------------------------------------------------------------

##
## TODO: Refactor the certificate generation and installation in smaller
## functions and move them (including enums) to ClusterSetupUtilities.psm1 module.
##
param
(
    [Parameter(Mandatory=$True, ParameterSetName = "Install")]
    [switch] $Install,
    
    [Parameter(Mandatory=$True, ParameterSetName = "Clean")]
    [switch] $Clean,

    [Parameter(Mandatory=$False)]
    [string] $CertSubjectName = "CN=ServiceFabricDevClusterCert"
)

function Cleanup-Cert([string] $CertSubjectName)
{
    Write-Host "Cleaning existing certificates..."

    $cerLocations = @("cert:\LocalMachine\My", "cert:\LocalMachine\root", "cert:\LocalMachine\CA", "cert:\CurrentUser\My")

    foreach($cerLoc in $cerLocations)
    {
        Get-ChildItem -Path $cerLoc | ? { $_.Subject -like "*$CertSubjectName*" } | Remove-Item
    }

    Write-Host "Certificates removed."
}

$warningMessage = @"
This will install certificate with '$CertSubjectName' in following stores:
    
    # LocalMachine\My
    # LocalMachine\root &
    # CurrentUser\My

The CleanCluster.ps1 will clean these certificates or you can clean them up using script 'CertSetup.ps1 -Clean -CertSubjectName $CertSubjectName'.

"@

$X509KeyUsageFlags = @{
DIGITAL_SIGNATURE = 0x80
KEY_ENCIPHERMENT = 0x20
DATA_ENCIPHERMENT = 0x10
}

$X509KeySpec = @{
NONE = 0
KEYEXCHANGE = 1
SIGNATURE = 2
}

$X509PrivateKeyExportFlags = @{
EXPORT_NONE = 0
EXPORT_FLAG = 0x1
PLAINTEXT_EXPORT_FLAG = 0x2
ARCHIVING_FLAG = 0x4
PLAINTEXT_ARCHIVING_FLAG = 0x8
}

$X509CertificateEnrollmentContext = @{
USER = 0x1
MACHINE = 0x2
ADMINISTRATOR_FORCE_MACHINE = 0x3
}

$EncodingType = @{
STRING_BASE64HEADER = 0
STRING_BASE64 = 0x1
STRING_BINARY = 0x2
STRING_BASE64REQUESTHEADER = 0x3
STRING_HEX = 0x4
STRING_HEXASCII = 0x5
STRING_BASE64_ANY = 0x6
STRING_ANY = 0x7
STRING_HEX_ANY = 0x8
STRING_BASE64X509CRLHEADER = 0x9
STRING_HEXADDR = 0xa
STRING_HEXASCIIADDR = 0xb
STRING_HEXRAW = 0xc
STRING_NOCRLF = 0x40000000
STRING_NOCR = 0x80000000
}

$InstallResponseRestrictionFlags = @{
ALLOW_NONE = 0x00000000
ALLOW_NO_OUTSTANDING_REQUEST = 0x00000001
ALLOW_UNTRUSTED_CERTIFICATE = 0x00000002
ALLOW_UNTRUSTED_ROOT = 0x00000004
}

if($Install)
{
    #cleanup previous installs of the certificate
    Cleanup-Cert -CertSubjectName $CertSubjectName
    
    Write-Host "Installing new certificates..."
    Write-Warning $warningMessage
    
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $name = new-object -com "X509Enrollment.CX500DistinguishedName"
    $name.Encode($CertSubjectName, 0x00100000)

    $key = new-object -com "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    $key.ExportPolicy = $X509PrivateKeyExportFlags.PLAINTEXT_EXPORT_FLAG
    $key.KeySpec = $X509KeySpec.KEYEXCHANGE
    $key.Length = 1024
    $sd = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0xd01f01ff;;;NS)(A;;0xd01f01ff;;;" + $identity.User.Value + ")"
    $key.SecurityDescriptor = $sd
    $key.MachineContext = $TRUE
    $key.Create()

    #set server auth keyspec
    $serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = new-object -com "X509Enrollment.CObjectIds.1"

    $ekuoids.add($serverauthoid)

    $clientauthoid = new-object -com "X509Enrollment.CObjectId.1"
    $clientauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.2")

    $ekuoids.add($clientauthoid)

    $ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $keyUsageExt = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
    $keyUsageExt.InitializeEncode($X509KeyUsageFlags.KEY_ENCIPHERMENT -bor $X509KeyUsageFlags.DIGITAL_SIGNATURE)

    $certTemplateName = ""
    $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey($X509CertificateEnrollmentContext.MACHINE, $key, $certTemplateName)
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $notbefore = get-date
    $ts = new-timespan -Days 2
    $cert.NotBefore = $notbefore.Subtract($ts)
    $cert.NotAfter = $cert.NotBefore.AddYears(1)
    $cert.X509Extensions.Add($ekuext)
    $cert.X509Extensions.Add($keyUsageExt)
    $cert.Encode()

    #install certificate in LocalMachine My store
    $enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)

    $certdata = $enrollment.CreateRequest($EncodingType.STRING_BASE64HEADER)
    
    $password = ""
    $enrollment.InstallResponse($InstallResponseRestrictionFlags.ALLOW_UNTRUSTED_CERTIFICATE, $certdata, $EncodingType.STRING_BASE64HEADER, $password)

    if (!$?)
    {
        Write-Warning "Failed to create certificates required for cluster"
        return
    }

    $srcStoreScope = "LocalMachine"
    $srcStoreName = "My"

    $srcStore = New-Object System.Security.Cryptography.X509Certificates.X509Store $srcStoreName, $srcStoreScope
    $srcStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    $cert = $srcStore.certificates -match "$CertSubjectName"
    $dstStoreScope = "LocalMachine"
    $dstStoreName = "root"

    #copy cert to root store so chain build succeeds
    $dstStore = New-Object System.Security.Cryptography.X509Certificates.X509Store $dstStoreName, $dstStoreScope
    $dstStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    foreach($c in $cert)
    {
        $dstStore.Add($c)
    }

    $dstStore.Close()

    $dstStoreScope = "CurrentUser"
    $dstStoreName = "My"

    $dstStore = New-Object System.Security.Cryptography.X509Certificates.X509Store $dstStoreName, $dstStoreScope
    $dstStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    foreach($c in $cert)
    {
        $dstStore.Add($c)
    }
    $srcStore.Close()
    $dstStore.Close()
}

if($Clean)
{
    Cleanup-Cert -CertSubjectName $CertSubjectName
}
# SIG # Begin signature block
# MIIdpgYJKoZIhvcNAQcCoIIdlzCCHZMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDF2wt3qjQt2PQRN/LFBQ15mU
# nxOgghhqMIIE2jCCA8KgAwIBAgITMwAAAQii+Uk6wLzpWAAAAAABCDANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTgwODIzMjAyMDI3
# WhcNMTkxMTIzMjAyMDI3WjCByjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# LTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046QTg0MS00QkI0LUNBOTMxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIHNlcnZpY2UwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQC7nYVW8D1vF9H+Np9rsDfXj5qO3efQTdBKUy8kK5zu2QbT
# qQrAtPz32S1pGznILaw9Vroc0RL+bHD+A+3G1+hk35brsgTa1HR/NeHWJc8FXBLz
# VkeNz0oZvHJ9WKMLsQlRa298hhG342GRgw222kwOXKFo0GimWuTkiJp24p98iEvg
# IYQavN3qSM6giFZONzqwyEJARo9Eu9KHppS2sC7AR8asAZfkBqpdwbw1DnrPcr01
# IimEEVHBqdZPsLhbg0rkIDCy0XajW0HsaisIJgpS3LePUlVnmiio0mEH0s4ASJ/5
# B/sca7/hSOcTclznzJXwSgMgM7/xxKWzZImdQDiZAgMBAAGjggEJMIIBBTAdBgNV
# HQ4EFgQUryk+Y1deSQhnMh4mC/394aUdl2QwHwYDVR0jBBgwFoAUIzT42VJGcArt
# QPt2+7MrsMM1sw8wVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC5taWNyb3Nv
# ZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljcm9zb2Z0VGltZVN0YW1wUENBLmNy
# bDBYBggrBgEFBQcBAQRMMEowSAYIKwYBBQUHMAKGPGh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljcm9zb2Z0VGltZVN0YW1wUENBLmNydDATBgNV
# HSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0BAQUFAAOCAQEAMNTUvMQ68dXnRkqO
# LqksPUC9I2MhjMGl4bF2s8xtG/aCP1iW9RdXOe/dWHhbzMTKlBUhxRJsxPv4Ebgp
# fH+4Oy3VFiHi3V5HvZlbSAqvd+mmYjpCh4nfwFV4YMfTk09eiHkkriORgYYwacpj
# 7rqcV6fuSLchQ+qjvPkQXm090rmnmC3zQaKtRP3p4hd52xCXMUuoYRqeyeS34+3+
# WHWLYKxHo81yTFi/SZc3+sUNOmrWbVzHK3osyTsNS0XF3BHNni19Wt0KlkdnCMFe
# Qs99GPcYH3nXKjNaTPQ/c8eVJbJE0brjYTGu78wKUBkpGs40Kbx+VuJ2Eb8VTPaU
# aCc3CjCCBf8wggPnoAMCAQICEzMAAAEDXiUcmR+jHrgAAAAAAQMwDQYJKoZIhvcN
# AQELBQAwfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYG
# A1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTAeFw0xODA3MTIy
# MDA4NDhaFw0xOTA3MjYyMDA4NDhaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xHjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANGUdjbmhqs2/mn5RnyLiFDLkHB/
# sFWpJB1+OecFnw+se5eyznMK+9SbJFwWtTndG34zbBH8OybzmKpdU2uqw+wTuNLv
# z1d/zGXLr00uMrFWK040B4n+aSG9PkT73hKdhb98doZ9crF2m2HmimRMRs621TqM
# d5N3ZyGctloGXkeG9TzRCcoNPc2y6aFQeNGEiOIBPCL8r5YIzF2ZwO3rpVqYkvXI
# QE5qc6/e43R6019Gl7ziZyh3mazBDjEWjwAPAf5LXlQPysRlPwrjo0bb9iwDOhm+
# aAUWnOZ/NL+nh41lOSbJY9Tvxd29Jf79KPQ0hnmsKtVfMJE75BRq67HKBCMCAwEA
# AaOCAX4wggF6MB8GA1UdJQQYMBYGCisGAQQBgjdMCAEGCCsGAQUFBwMDMB0GA1Ud
# DgQWBBRHvsDL4aY//WXWOPIDXbevd/dA/zBQBgNVHREESTBHpEUwQzEpMCcGA1UE
# CxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xFjAUBgNVBAUTDTIz
# MDAxMis0Mzc5NjUwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYD
# VR0fBE0wSzBJoEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# cmwvTWljQ29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRV
# MFMwUQYIKwYBBQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y2VydHMvTWljQ29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8E
# AjAAMA0GCSqGSIb3DQEBCwUAA4ICAQCf9clTDT8NJuyiRNgN0Z9jlgZLPx5cxTOj
# pMNsrx/AAbrrZeyeMxAPp6xb1L2QYRfnMefDJrSs9SfTSJOGiP4SNZFkItFrLTuo
# LBWUKdI3luY1/wzOyAYWFp4kseI5+W4OeNgMG7YpYCd2NCSb3bmXdcsBO62CEhYi
# gIkVhLuYUCCwFyaGSa/OfUUVQzSWz4FcGCzUk/Jnq+JzyD2jzfwyHmAc6bAbMPss
# uwculoSTRShUXM2W/aDbgdi2MMpDsfNIwLJGHF1edipYn9Tu8vT6SEy1YYuwjEHp
# qridkPT/akIPuT7pDuyU/I2Au3jjI6d4W7JtH/lZwX220TnJeeCDHGAK2j2w0e02
# v0UH6Rs2buU9OwUDp9SnJRKP5najE7NFWkMxgtrYhK65sB919fYdfVERNyfotTWE
# cfdXqq76iXHJmNKeWmR2vozDfRVqkfEU9PLZNTG423L6tHXIiJtqv5hFx2ay1//O
# kpB15OvmhtLIG9snwFuVb0lvWF1pKt5TS/joynv2bBX5AxkPEYWqT5q/qlfdYMb1
# cSD0UaiayunR6zRHPXX6IuxVP2oZOWsQ6Vo/jvQjeDCy8qY4yzWNqphZJEC4Omek
# B1+g/tg7SRP7DOHtC22DUM7wfz7g2QjojCFKQcLe645b7gPDHW5u5lQ1ZmdyfBrq
# UvYixHI/rjCCBgcwggPvoAMCAQICCmEWaDQAAAAAABwwDQYJKoZIhvcNAQEFBQAw
# XzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29m
# dDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# MB4XDTA3MDQwMzEyNTMwOVoXDTIxMDQwMzEzMDMwOVowdzELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn6Fssd/b
# SJIqfGsuGeG94uPFmVEjUK3O3RhOJA/u0afRTK10MCAR6wfVVJUVSZQbQpKumFww
# JtoAa+h7veyJBw/3DgSY8InMH8szJIed8vRnHCz8e+eIHernTqOhwSNTyo36Rc8J
# 0F6v0LBCBKL5pmyTZ9co3EZTsIbQ5ShGLieshk9VUgzkAyz7apCQMG6H81kwnfp+
# 1pez6CGXfvjSE/MIt1NtUrRFkJ9IAEpHZhEnKWaol+TTBoFKovmEpxFHFAmCn4Tt
# VXj+AZodUAiFABAwRu233iNGu8QtVJ+vHnhBMXfMm987g5OhYQK1HQ2x/PebsgHO
# IktU//kFw8IgCwIDAQABo4IBqzCCAacwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
# FgQUIzT42VJGcArtQPt2+7MrsMM1sw8wCwYDVR0PBAQDAgGGMBAGCSsGAQQBgjcV
# AQQDAgEAMIGYBgNVHSMEgZAwgY2AFA6sgmBAVieX5SUT/CrhClOVWeSkoWOkYTBf
# MRMwEQYKCZImiZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0
# MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmC
# EHmtFqFKoKWtTHNY9AcTLmUwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC5t
# aWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQu
# Y3JsMFQGCCsGAQUFBwEBBEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraS9jZXJ0cy9NaWNyb3NvZnRSb290Q2VydC5jcnQwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQEFBQADggIBABCXisNcA0Q23em0rXfb
# znlRTQGxLnRxW20ME6vOvnuPuC7UEqKMbWK4VwLLTiATUJndekDiV7uvWJoc4R0B
# hqy7ePKL0Ow7Ae7ivo8KBciNSOLwUxXdT6uS5OeNatWAweaU8gYvhQPpkSokInD7
# 9vzkeJkuDfcH4nC8GE6djmsKcpW4oTmcZy3FUQ7qYlw/FpiLID/iBxoy+cwxSnYx
# PStyC8jqcD3/hQoT38IKYY7w17gX606Lf8U1K16jv+u8fQtCe9RTciHuMMq7eGVc
# WwEXChQO0toUmPU8uWZYsy0v5/mFhsxRVuidcJRsrDlM1PZ5v6oYemIp76KbKTQG
# dxpiyT0ebR+C8AvHLLvPQ7Pl+ex9teOkqHQ1uE7FcSMSJnYLPFKMcVpGQxS8s7Ow
# TWfIn0L/gHkhgJ4VMGboQhJeGsieIiHQQ+kr6bv0SMws1NgygEwmKkgkX1rqVu+m
# 3pmdyjpvvYEndAYR7nYhv5uCwSdUtrFqPYmhdmG0bqETpr+qR/ASb/2KMmyy/t9R
# yIwjyWa9nR2HEmQCPS2vWY+45CHltbDKY7R4VAXUQS5QrJSwpXirs6CWdRrZkocT
# dSIvMqgIbqBbjCW/oO+EyiHW6x5PyZruSeD3AWVviQt9yGnI5m7qp5fOMSn/DsVb
# XNhNG6HY+i+ePy5VFmvJE6P9MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCBKYwggSiAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAEDXiUcmR+jHrgAAAAAAQMwCQYFKw4DAhoFAKCB
# ujAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU8obQYnwS4B5NkCcPWhoHZo2OYRcw
# WgYKKwYBBAGCNwIBDDFMMEqgJIAiAE0AaQBjAHIAbwBzAG8AZgB0ACAAVwBpAG4A
# ZABvAHcAc6EigCBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vd2luZG93czANBgkq
# hkiG9w0BAQEFAASCAQAhrawdPjDzysxWo2avDlf9G3QYIwnu/6gicbY/BezINmrn
# b3OA2YRt9F163G/linyCYsbwt0r+g6mZjEZb2O67/qC7e7k2zM9vttFyKlUh1gLP
# SmosuMH1gD/cp13VsyLGpIn9a2aPDMCBUiFMfYXNluJJrUo8Y/GqgN56c6LlJn4E
# 6q1UB6w4uEEYt60CE6WTYOEjTAd41eICIfdu6wJCRhAXe6aXJ/zhEWfIHEMHEDAW
# qHcFtrNqI9hZv5BDsfLjegwWARsi6J/wtCjIxVjou9MwgGCEgdHSK1PCWq/sC9aL
# 1wfPzYesd5o5qvwX2Mp6wjs8EFTnzj7pC6qaDH6OoYICKDCCAiQGCSqGSIb3DQEJ
# BjGCAhUwggIRAgEBMIGOMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xITAfBgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQQITMwAAAQii
# +Uk6wLzpWAAAAAABCDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3
# DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgxMjE0MDA0MTU2WjAjBgkqhkiG9w0BCQQx
# FgQU3hRad0wiVU0Bq9EAI/U0ayGV450wDQYJKoZIhvcNAQEFBQAEggEAiSikiEkD
# EZ7rwTygnmHheI62JM5rLhzufbDjnKl/Dn0bhDVjW0uTTkVgL1JjCqfotfhEHoK0
# 3Ac0pPhqWxbo7bZfVF6/C6QF0y88whf6Y557LIQF6gqXDdHGtFwONMVKdrc//iEA
# LTCGiGi9Y1HY9CRWqgUQbcS7v+Dd6gzX1GgWjMZ7PRUdxRFHTG783Qr7fqGvW2kB
# Dsosb8vJvh+9cgGJvlsJYXnVGQV5B+XYRcbvG2GSmx7gmOdkbanFyuNR8tly3eUK
# j9J6yEOzhy5/89mMpATzd/vsvJQ9JJpndxeCCwI+fL5xhL8QFZO96kAGdG4D4Xez
# T0jWvpO2+yIycw==
# SIG # End signature block
