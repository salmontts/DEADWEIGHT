# DEADWEIGHT - Windows Cleaner

![DEADWEIGHT GUI](screenshot.png)

## Podstawowe użycie (dla wszystkich)
1. 🚀 **Pobierz** najnowszą wersję `deadweight.exe`
2. 🖱️ **Uruchom** (kliknij dwukrotnie)
3. 🔘 Kliknij **CLEAN**
4. ☕ Poczekaj na zakończenie (zwykle 1-3 minuty)

Program automatycznie wykonuje:
- ✔️ Czyszczenie plików tymczasowych (%TEMP%, Prefetch)
- ✔️ Usuwanie zbędnych wpisów autostartu
- ✔️ Logowanie wszystkich operacji do `deadweight.log`

## 🔧 Sekcja dla Zaawansowanych

### 💻 Tryb konsolowy (CMD/PowerShell)
``'`cmd
## Pełne czyszczenie systemu (wymaga admina)
deadweight.exe --purge

## Skanowanie folderu (domyślnie 30+ dni nieużywane)
deadweight.exe --scan "C:\Program Files" [DAYS]

## Monitorowanie procesów w czasie rzeczywistym
deadweight.exe --live 60

## Szczegółowa analiza procesu
deadweight.exe --lupa chrome.exe

## Generowanie pełnego raportu
deadweight.exe --report > raport.txt

# 🛠️ Zaawansowane funkcje
cmd

## Agresywne czyszczenie (uwaga!):
deadweight.exe --purge --force

## Usuwanie konkretnych aplikacji:
deadweight.exe --uninstall "Adobe Flash"

## Czyszczenie rejestru:
deadweight.exe --regclean

## Usuwanie nieużywanych sterowników:
deadweight.exe --drvclean

# 🔍 Techniczne szczegóły implementacji

Program wykorzystuje:

    Niskopoziomowe API Windows (Win32/Native API)

    Rekurencyjne skanowanie systemu plików NTFS

    Bezpośredni dostęp do rejestru

    Analizę prefetch i event logs

    WMI do zarządzania procesami

# 📝 Przykładowe zastosowania
powershell

## Zaplanowane czyszczenie (Task Scheduler)
SCHTASKS /Create /SC WEEKLY /TN "Deadweight Clean" /TR "deadweight.exe --purge" /ST 23:00

## Integracja z skryptami PS:
Invoke-DeadweightClean -Mode Deep -LogPath "C:\logs\clean.log"

## Własne filtry czyszczenia:
deadweight.exe --custom-filter "*.tmp,*.log,~*.*"

# ⚠️ Bezpieczeństwo i logi

Program generuje szczegółowe logi:

    deadweight.log - podstawowe operacje

    deadweight_purge.log - pełny zapis czyszczenia

    deadweight_errors.log - błędy i ostrzeżenia

Zawsze sprawdzaj logi przed usunięciem ważnych danych!

📌 Wersja: 2.1 (2023-11-20)
📜 Licencja: MIT (pełne prawa do modyfikacji)
