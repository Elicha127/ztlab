# Domain context
$DomainDN = "DC=germe-tech,DC=local"

# Create OUs
$OUs = @(
  "OU=Accounts,$DomainDN",
  "OU=ServiceAccounts,$DomainDN",
  "OU=Groups,$DomainDN",
  "OU=Servers,$DomainDN",
  "OU=Workstations,$DomainDN"
)
foreach ($ouDN in $OUs) {
  if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouDN)" -ErrorAction SilentlyContinue)) {
    $name = ($ouDN.Split(",")[0] -split "=")[1]
    $path = $ouDN.Substring($ouDN.IndexOf(",")+1)
    New-ADOrganizationalUnit -Name $name -Path $path
  }
}

# Create security groups
$Groups = @(
  @{ Name="ServerAdmins";      Path="OU=Groups,$DomainDN" },
  @{ Name="Helpdesk";          Path="OU=Groups,$DomainDN" },
  @{ Name="DevOps";            Path="OU=Groups,$DomainDN" },
  @{ Name="Monitoring";        Path="OU=Groups,$DomainDN" },
  @{ Name="VPN_Users";         Path="OU=Groups,$DomainDN" },
  @{ Name="PrometheusReaders"; Path="OU=Groups,$DomainDN" }
)
foreach ($g in $Groups) {
  if (-not (Get-ADGroup -Identity $g.Name -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security -Path $g.Path
  }
}

# Password generator
function New-RandomSecurePassword { param([int]$Length=22)
  $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-='
  -join (1..$Length | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] })
}

# Service accounts
$ServiceAccounts = @(
  @{ Sam="prometheus_scrape"; Given="Prometheus"; Surname="Scrape"; Path="OU=ServiceAccounts,$DomainDN"; Groups=@("Monitoring","PrometheusReaders") },
  @{ Sam="grafana_bind";      Given="Grafana";    Surname="Bind";   Path="OU=ServiceAccounts,$DomainDN"; Groups=@("Monitoring") },
  @{ Sam="awx_service";       Given="AWX";        Surname="Service"; Path="OU=ServiceAccounts,$DomainDN"; Groups=@("DevOps","Monitoring") },
  @{ Sam="pfSenseBind";       Given="pfSense";    Surname="Bind";    Path="OU=ServiceAccounts,$DomainDN"; Groups=@() }
)
foreach ($svc in $ServiceAccounts) {
  if (-not (Get-ADUser -Identity $svc.Sam -ErrorAction SilentlyContinue)) {
    $pwdPlain = New-RandomSecurePassword
    $pwd = ConvertTo-SecureString $pwdPlain -AsPlainText -Force
    New-ADUser -Name $svc.Sam -SamAccountName $svc.Sam -GivenName $svc.Given -Surname $svc.Surname `
      -Path $svc.Path -AccountPassword $pwd -Enabled $true -PasswordNeverExpires $true
    Write-Host "ServiceAccount $($svc.Sam) password: $pwdPlain"
  }
  foreach ($grp in $svc.Groups) { Add-ADGroupMember -Identity $grp -Members $svc.Sam -ErrorAction SilentlyContinue }
}

# Human users
$Users = @(
  @{ Sam="elicha"; Given="Elicha"; Surname="Admin"; Path="OU=Accounts,$DomainDN"; Groups=@("ServerAdmins","DevOps") }
)
foreach ($u in $Users) {
  if (-not (Get-ADUser -Identity $u.Sam -ErrorAction SilentlyContinue)) {
    $pwdPlain = New-RandomSecurePassword
    $pwd = ConvertTo-SecureString $pwdPlain -AsPlainText -Force
    New-ADUser -Name $u.Sam -SamAccountName $u.Sam -GivenName $u.Given -Surname $u.Surname `
      -Path $u.Path -AccountPassword $pwd -Enabled $true -ChangePasswordAtLogon $true
    Write-Host "User $($u.Sam) initial password: $pwdPlain"
  }
  foreach ($grp in $u.Groups) { Add-ADGroupMember -Identity $grp -Members $u.Sam -ErrorAction SilentlyContinue }
}
