# Work around an RS5/PSReadline-2.0.0+beta2 bug (Spacebar is not marked 'essential')
Set-PSReadlineKeyHandler "Shift+SpaceBar" -ScriptBlock {
        [Microsoft.Powershell.PSConsoleReadLine]::Insert(' ')
}
