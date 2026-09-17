@echo off
cd C:\assessment-swo
git add .
git commit -m "backup automatico %date% %time%"
git push
pause