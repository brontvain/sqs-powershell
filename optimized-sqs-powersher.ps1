# Import AWS PowerShell module
Import-Module AWSPowerShell

# Configuration parameters
$QueueUrl = 'https://sqs.us-west-2.amazonaws.com/<accountID>/user-provision'
$Region = "us-west-2"

# AWS credentials - Use environment variables or AWS credential profile instead of hardcoding
# For testing, you can use these parameters with Receive-SQSMessage
# $AccessKey = $env:AWS_ACCESS_KEY_ID
# $SecretKey = $env:AWS_SECRET_ACCESS_KEY
# $SessionToken = $env:AWS_SESSION_TOKEN

# SQS message processing function
function Process-SQSMessage {
    [CmdletBinding()]
    param()
    
    try {
        # Get SQS message using AWS credentials from profile or environment variables
        $SQSMessage = Receive-SQSMessage -QueueUrl $QueueUrl -WaitTimeInSeconds 10 -MessageCount 1 -Region $Region
        
        if ($null -eq $SQSMessage) {
            Write-Output 'No messages available in the queue'
            return $null
        }
        
        # Parse message body
        $MessageBodyObject = $SQSMessage.Body | ConvertFrom-Json
        
        # Create user object with required properties
        $UserObject = [PSCustomObject]@{
            MessageId = $SQSMessage.MessageId
            ReceiptHandle = $SQSMessage.ReceiptHandle
            UserName = $MessageBodyObject.UserName
            DisplayName = $MessageBodyObject.DisplayName
            DateTimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Validate required properties exist
        if ([string]::IsNullOrEmpty($UserObject.UserName) -or [string]::IsNullOrEmpty($UserObject.DisplayName)) {
            Write-Warning "Required user properties missing from message: $($SQSMessage.MessageId)"
            return $null
        }
        
        return $UserObject
    }
    catch {
        Write-Error "Error processing SQS message: $_"
        return $null
    }
}

# AD User management function
function Add-UpdateADUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$UserObject
    )
    
    try {
        # Check if user exists
        $existingUser = Get-ADUser -Filter "SamAccountName -eq '$($UserObject.UserName)'" -ErrorAction SilentlyContinue
        
        if ($null -eq $existingUser) {
            # Create new user
            New-ADUser -SamAccountName $UserObject.UserName `
                      -Name $UserObject.UserName `
                      -DisplayName $UserObject.DisplayName `
                      -ChangePasswordAtLogon $true `
                      -PasswordNotRequired $true `
                      -Enabled $true
                      
            Write-Output "Created new AD user: $($UserObject.UserName)"
        }
        else {
            # Update existing user
            Set-ADUser -Identity $UserObject.UserName -DisplayName $UserObject.DisplayName
            Write-Output "Updated existing AD user: $($UserObject.UserName)"
        }
        
        # Delete message from queue after successful processing
        Remove-SQSMessage -QueueUrl $QueueUrl -ReceiptHandle $UserObject.ReceiptHandle -Region $Region
    }
    catch {
        Write-Error "Error managing AD user: $_"
    }
}

# Main execution block
function Main {
    # Process the SQS message
    $user = Process-SQSMessage
    
    # If a valid user object was returned, add/update in AD
    if ($null -ne $user) {
        Add-UpdateADUser -UserObject $user
    }
}

# Run the main function
Main
