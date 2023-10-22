function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256

        # Define the red flag file name
        $redFlagFileName = "_stop.txt"
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File) {
                        Write-Error -Message "File or folder not found!"
                        return
                    }

                    # Check if the path is a folder
                    if ($File.PSIsContainer) {
                        # Get all files recursively within the folder
                        $files = Get-ChildItem -Path $File.FullName -Recurse -File
                        foreach ($file in $files) {
                            # Skip processing if a red flag file is found
                            if (Test-Path (Join-Path $file.DirectoryName $redFlagFileName)) {
                                Write-Host "Operation stopped due to red flag file."
                                return
                            }

                            $plainBytes = [System.IO.File]::ReadAllBytes($file.FullName)
                            $outPath = $file.FullName + ".aes"

                            $encryptor = $aesManaged.CreateEncryptor()
                            $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                            $encryptedBytes = $aesManaged.IV + $encryptedBytes

                            [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                            (Get-Item $outPath).LastWriteTime = $file.LastWriteTime
                            Write-Output "File encrypted: $outPath"
                            Remove-Item -Path $file.FullName -Force
                        }
                        return
                    } else {
                        $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                        $outPath = $File.FullName + ".aes"
                    }
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    Write-Output "File encrypted to $outPath"
                    Remove-Item -Path $File.FullName -Force
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File) {
                        Write-Error -Message "File or folder not found!"
                        return
                    }

                    # Check if the path is a folder
                    if ($File.PSIsContainer) {
                        # Get all files recursively within the folder
                        $files = Get-ChildItem -Path $File.FullName -Recurse -File
                        foreach ($file in $files) {
                            # Skip processing if a red flag file is found
                            if (Test-Path (Join-Path $file.DirectoryName $redFlagFileName)) {
                                Write-Host "Operation stopped due to red flag file."
                                return
                            }

                            $cipherBytes = [System.IO.File]::ReadAllBytes($file.FullName)
                            $outPath = $file.FullName -replace ".aes"

                            $aesManaged.IV = $cipherBytes[0..15]
                            $decryptor = $aesManaged.CreateDecryptor()
                            $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)

                            [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                            (Get-Item $outPath).LastWriteTime = $file.LastWriteTime
                            Write-Output "File decrypted: $outPath"
                            Remove-Item -Path $file.FullName -Force
                        }
                        return
                    } else {
                        $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                        $outPath = $File.FullName -replace ".aes"
                    }
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    Write-Output "File decrypted to $outPath"
                    Remove-Item -Path $File.FullName -Force
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
