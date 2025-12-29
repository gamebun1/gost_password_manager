# Описание
Менеджер паролей на основе российских стандартов криптографии. В проекте задействован **"Кузнечик"**(ГОСТ 34.12-2015) в режиме CBC и **"Стрибог"**(ГОСТ 34.11-2012).

# Установка(Linux)
```bash
git clone https://github.com/gamebun1/gost_password_manager
cd gost_password_manager
pip install -r requirements.txt
```
Необходим установленный Tkinter, если его нет следуйте следующим инструкциям:

Debian based
```bash
sudo apt update
sudo apt install python3-tk
```
Fedora/Red Hat
```bash
sudo dnf install python3-tkinter
```
Arch Linux/Manjaro
```bash
sudo pacman -S tk
```
CentOS/RHEL
```bash
sudo yum install python3-tkinter
```

# Запуск
```bash
python3 main.py
```
