#Needed to download packages from powershell via install-module
#Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
#Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
#[Net.ServicePointManager]::SecurityProtocol

#Get-Help *SQS* | select -Property Name

#Install-Module AWSPowershell
Import-Module AWSPowerShell

Receive-SQSMessage -AttributeName SenderId, SentTimestamp -MessageAttributeName username -MessageCount 10 -QueueUrl https://sqs.us-west-2.amazonaws.com/429249580520/user-provision -AccessKey ASIAWH4KEZXUAYPPLA5X -SecretKey $SecretKey -SessionToken $SessionToken -Region us-west-2

$QueueUrl = 'https://sqs.us-west-2.amazonaws.com/<accountID>/user-provision'
$AccessKey = "<AccessKey>" 
$SecretKey = "<SecretKey>"
$SessionToken = "<SessionToken>"
$region = "us-west-2"

##### create object from SQS message
$SQSMessage = Receive-SQSMessage -QueueUrl $QueueUrl -WaitTimeInSeconds 10  -MessageCount 1 -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Region $Region
 
        if ($null -eq $SQSMessage)
        {
            return 'EMPTY'
        }
        else
        {
            $MessageBodyObject = $($SQSMessage.Body) | ConvertFrom-Json
 
            $props = @{
                MessageId = $SQSMessage.MessageId
                ReceiptHandle = $SQSMessage.ReceiptHandle
                UserName = $MessageBodyObject.UserName
                DisplayName = $MessageBodyObject.DisplayName
                DateTimeStamp = (Get-Date -Format yyyy-MM-dd) + " " + (Get-Date -Format HH:mm:ss)
            }
 
            $UserObject = New-Object PSObject -Property $props
        }

# Insert user to AD
New-ADUser -SamAccountName $UserObject.UserName -ChangePasswordAtLogon 1 -DisplayName $UserObject.DisplayName -Name $UserObject.UserName -PasswordNotRequired 1

#Update AD User
Get-ADUser $UserObject.UserName-Properties Surname, GivenName, Initials | % {New-ADUser -Identity $_ -DisplayName $UserObject.DisplayName}

