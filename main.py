import os
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLineEdit, QPushButton, QLabel,
    QVBoxLayout, QHBoxLayout, QMessageBox, QInputDialog, QTextEdit
)

FILE = "users.txt"
users = {}


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.blocked = False
        self.restrictions = True
        self.variant = 0


# ================= Загрузка / сохранение =================
def load_users():
    global users
    if not os.path.exists(FILE):
        return
    with open(FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(";")
            if len(parts) >= 4:
                username, password = parts[0], parts[1]
                blocked = parts[2].lower() == "true"
                restrictions = parts[3].lower() == "true"
                variant = int(parts[4]) if len(parts) >= 5 and parts[4].isdigit() else 0
                u = User(username, password)
                u.blocked = blocked
                u.restrictions = restrictions
                u.variant = variant
                users[username] = u


def save_users():
    with open(FILE, "w", encoding="utf-8") as f:
        for u in users.values():
            f.write(f"{u.username};{u.password};{u.blocked};{u.restrictions};{u.variant}\n")


# ================= Проверка пароля =================
def password_missing_components(passw):
    missing = []
    if not re.search(r"[A-Za-z]", passw):
        missing.append("латинские буквы (A-Z / a-z)")
    if not re.search(r"[А-Яа-яЁё]", passw):
        missing.append("кириллические символы (А-Я / а-я)")
    if not re.search(r"[a-zа-яё]", passw):
        missing.append("строчные буквы")
    if not re.search(r"[A-ZА-ЯЁ]", passw):
        missing.append("прописные буквы")
    if not re.search(r"\d", passw):
        missing.append("цифры (0-9)")
    if not re.search(r"[.,;:!?]", passw):
        missing.append("знаки препинания")
    if not re.search(r"[+\-*/%]", passw):
        missing.append("знаки арифметики (+ - * / %)")
    return missing


# ================= Окно входа =================
class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Вход")
        self.setGeometry(500, 300, 300, 150)

        layout = QVBoxLayout()

        h_user = QHBoxLayout()
        h_user.addWidget(QLabel("Имя:"))
        self.entry_user = QLineEdit()
        h_user.addWidget(self.entry_user)
        layout.addLayout(h_user)

        h_pass = QHBoxLayout()
        h_pass.addWidget(QLabel("Пароль:"))
        self.entry_pass = QLineEdit()
        self.entry_pass.setEchoMode(QLineEdit.Password)
        h_pass.addWidget(self.entry_pass)
        layout.addLayout(h_pass)

        self.btn_login = QPushButton("Войти")
        self.btn_login.clicked.connect(self.on_login)
        layout.addWidget(self.btn_login)

        self.setLayout(layout)

    def on_login(self):
        username = self.entry_user.text().strip()
        password = self.entry_pass.text()

        if username not in users:
            QMessageBox.critical(self, "Ошибка", "Нет такого пользователя")
            return
        u = users[username]
        if u.blocked:
            QMessageBox.critical(self, "Ошибка", "Аккаунт заблокирован")
            return
        if u.password != password:
            QMessageBox.critical(self, "Ошибка", "Неверный пароль")
            return

        self.close()
        if username == "ADMIN":
            self.admin = AdminMenu()
            self.admin.show()
        else:
            self.user = UserMenu(u)
            self.user.show()


# ================= Админ меню =================
class AdminMenu(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Админ меню")
        self.setGeometry(500, 300, 300, 250)

        layout = QVBoxLayout()

        btn_add = QPushButton("Добавить пользователя")
        btn_add.clicked.connect(self.add_user)
        layout.addWidget(btn_add)

        btn_list = QPushButton("Просмотр пользователей")
        btn_list.clicked.connect(self.show_users)
        layout.addWidget(btn_list)

        btn_block = QPushButton("Блокировать/Разблокировать пользователя")
        btn_block.clicked.connect(self.toggle_block)
        layout.addWidget(btn_block)

        btn_help = QPushButton("Справка / О программе")
        btn_help.clicked.connect(self.show_about)
        layout.addWidget(btn_help)

        btn_exit = QPushButton("Выход")
        btn_exit.clicked.connect(self.go_login)
        layout.addWidget(btn_exit)

        self.setLayout(layout)

    def add_user(self):
        name, ok = QInputDialog.getText(self, "Добавление пользователя", "Имя:")
        if not ok or not name:
            return
        if name in users:
            QMessageBox.critical(self, "Ошибка", "Такой пользователь уже есть")
            return
        passw, ok = QInputDialog.getText(self, "Добавление пользователя", "Пароль:", QLineEdit.Password)
        if not ok or not passw:
            return
        missing = password_missing_components(passw)
        if missing:
            QMessageBox.critical(self, "Ошибка", "Пароль не соответствует требованиям:\n" + "\n".join(missing))
            return
        u = User(name, passw)
        users[name] = u
        save_users()
        QMessageBox.information(self, "OK", "Пользователь добавлен")

    def show_users(self):
        text = "username;password;blocked;restrictions;variant\n\n"
        for u in users.values():
            text += f"{u.username} | пароль={'(пусто)' if not u.password else u.password} | блок={u.blocked} | ограничения={u.restrictions} | variant={u.variant}\n"
        dlg = QTextEdit()
        dlg.setPlainText(text)
        dlg.setReadOnly(True)
        dlg.setWindowTitle("Список пользователей")
        dlg.resize(500, 300)
        dlg.show()
        self.child = dlg

    def toggle_block(self):
        name, ok = QInputDialog.getText(self, "Блокировка", "Имя пользователя:")
        if not ok or not name:
            return
        if name not in users:
            QMessageBox.critical(self, "Ошибка", "Нет такого пользователя")
            return
        u = users[name]
        u.blocked = not u.blocked
        save_users()
        QMessageBox.information(self, "OK", f"Пользователь {name} {'заблокирован' if u.blocked else 'разблокирован'}")

    def show_about(self):
        QMessageBox.information(self, "О программе",
                                "Программа разграничения полномочий (лабораторная)\nАвтор: студент\nВарианты 11-15: применяются одновременно")

    def go_login(self):
        save_users()
        self.close()
        self.login = LoginWindow()
        self.login.show()


# ================= Меню пользователя =================
class UserMenu(QWidget):
    def __init__(self, user):
        super().__init__()
        self.user = user
        self.setWindowTitle(f"Меню пользователя: {user.username}")
        self.setGeometry(500, 300, 300, 200)

        layout = QVBoxLayout()

        btn_change = QPushButton("Сменить пароль")
        btn_change.clicked.connect(self.change_password)
        layout.addWidget(btn_change)

        btn_rules = QPushButton("Показать требования к паролю")
        btn_rules.clicked.connect(self.show_rules)
        layout.addWidget(btn_rules)

        btn_exit = QPushButton("Выход")
        btn_exit.clicked.connect(self.go_login)
        layout.addWidget(btn_exit)

        self.setLayout(layout)

    def change_password(self):
        old, ok = QInputDialog.getText(self, "Смена пароля", "Старый пароль:", QLineEdit.Password)
        if not ok:
            return
        if old != self.user.password:
            QMessageBox.critical(self, "Ошибка", "Неверный старый пароль")
            return

        p1, ok = QInputDialog.getText(self, "Смена пароля", "Новый пароль:", QLineEdit.Password)
        if not ok:
            return
        p2, ok = QInputDialog.getText(self, "Смена пароля", "Повторите пароль:", QLineEdit.Password)
        if not ok:
            return
        if p1 != p2:
            QMessageBox.critical(self, "Ошибка", "Пароли не совпадают")
            return

        missing = password_missing_components(p1)
        if missing:
            QMessageBox.critical(self, "Ошибка", "Пароль не соответствует требованиям:\n" + "\n".join(missing))
            return

        self.user.password = p1
        save_users()
        QMessageBox.information(self, "OK", "Пароль изменён")

    def show_rules(self):
        QMessageBox.information(self, "Правила", 
                                "Требования к паролю:\n"
                                "• Латиница (a-z, A-Z)\n"
                                "• Кириллица (а-я, А-Я)\n"
                                "• Строчные и заглавные буквы\n"
                                "• Цифры (0-9)\n"
                                "• Знаки препинания (. , ; : ! ?)\n"
                                "• Арифметические знаки (+ - * / %)")

    def go_login(self):
        save_users()
        self.close()
        self.login = LoginWindow()
        self.login.show()


# ================= MAIN =================
if __name__ == "__main__":
    load_users()
    if "ADMIN" not in users:
        users["ADMIN"] = User("ADMIN", "")
        save_users()

    app = QApplication(sys.argv)
    win = LoginWindow()
    win.show()
    sys.exit(app.exec_())
