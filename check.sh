#!/data/data/com.termux/files/usr/bin/bash
echo "🛡️ OpenShield AI"
echo "----------------"
echo "1. Check security.py"
echo "2. Check bot/app.py"
echo "3. Run bot"
echo "4. Exit"
read -p "Choose: " choice

case $choice in
  1) python -m py_compile modules/security.py && echo "✅ security.py OK" ;;
  2) python -m py_compile bot/app.py && echo "✅ app.py OK" ;;
  3) python bot/app.py ;;
  4) exit ;;
  *) echo "❌ Invalid option" ;;
esac
