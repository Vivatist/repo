
# Остановка сервиса
Write-Host "Останавливаем сервис NovaVPN..."
sc.exe stop NovaVPN 2>$null
Start-Sleep -Seconds 1

# Ждём пока процесс завершится
$attempts = 0
while ($attempts -lt 10) {
    $proc = Get-Process -Name "novavpn-service" -ErrorAction SilentlyContinue
    if (-not $proc) { break }
    Write-Host "Ждём завершения процесса..."
    Start-Sleep -Seconds 1
    $attempts++
}

# Принудительно, если не завершился
$proc = Get-Process -Name "novavpn-service" -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "Принудительная остановка..."
    Stop-Process -Name "novavpn-service" -Force
    Start-Sleep -Seconds 1
}

# Копируем новые бинарники
Write-Host "Обновляем бинарники..."
Copy-Item "c:\Users\andre\repo\vpn-client-windows\dist\novavpn-service.exe" "C:\Program Files\NovaVPN\novavpn-service.exe" -Force
Copy-Item "c:\Users\andre\repo\vpn-client-windows\dist\NovaVPN.exe" "C:\Program Files\NovaVPN\NovaVPN.exe" -Force

# Проверяем
$src = (Get-Item "c:\Users\andre\repo\vpn-client-windows\dist\novavpn-service.exe").LastWriteTime
$dst = (Get-Item "C:\Program Files\NovaVPN\novavpn-service.exe").LastWriteTime
Write-Host "Исходный: $src"
Write-Host "Установленный: $dst"

# Запускаем сервис
Write-Host "Запускаем сервис NovaVPN..."
sc.exe start NovaVPN

Write-Host "Готово!"
Start-Sleep -Seconds 2
