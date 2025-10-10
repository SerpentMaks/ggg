import sys
import os
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLineEdit, QPushButton, QLabel,
    QVBoxLayout, QHBoxLayout, QMessageBox, QInputDialog, QTextEdit,
    QGroupBox, QRadioButton, QButtonGroup
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


# ================= Криптография: справка и алгоритмы =================
SYMMETRIC_ALGOS = [
    "Цезарь",
    "Виженер",
    "Playfair",
    "DES",
    "AES",
]

ASYMMETRIC_ALGOS = [
    "RSA",
    "ElGamal",
    "Diffie–Hellman",
    "ECC",
    "DSA",
]

THEORY_TEXT = {
    "symmetric": {
        "Цезарь": (
            "Шифр Цезаря — простой сдвиг каждой буквы алфавита на фиксированное "
            "число позиций по кругу. Пример: при сдвиге 3 A→D."
        ),
        "Виженер": (
            "Шифр Виженера использует табличную замену с ключевым словом. Каждая "
            "позиция текста сдвигается на величину, определяемую буквой ключа."
        ),
        "Playfair": (
            "Playfair — биграммный шифр замены, использующий 5×5 таблицу, "
            "заполненную по ключу. Текст шифруется парами букв."
        ),
        "DES": (
            "DES — блочный симметричный шифр (64-битные блоки, ключ 56 бит). Сейчас "
            "считается устаревшим из‑за малой стойкости к перебору."
        ),
        "AES": (
            "AES — современный блочный симметричный стандарт (блок 128 бит, ключи "
            "128/192/256). Использует сеть подстановок и перестановок."
        ),
    },
    "asymmetric": {
        "RSA": (
            "RSA — асимметричный алгоритм на основе сложности факторизации. "
            "Использует пару ключей: публичный (e,n) и приватный (d,n)."
        ),
        "ElGamal": (
            "ElGamal — асимметричная схема на дискретных логарифмах. Поддерживает "
            "шифрование и электронную подпись."
        ),
        "Diffie–Hellman": (
            "Протокол Диффи–Хеллмана — механизм безопасного согласования "
            "общего симметричного ключа по открытому каналу."
        ),
        "ECC": (
            "Криптография на эллиптических кривых — асимметричные схемы, где стойкость "
            "основана на сложности логарифма на кривой; ключи короче, чем у RSA."
        ),
        "DSA": (
            "DSA — стандарт электронной подписи на дискретных логарифмах. Для "
            "шифрования напрямую не используется, только для подписи."
        ),
    },
}

# Симметричный «под капотом»: Цезарь со сдвигом 3
LATIN_LOWER = "abcdefghijklmnopqrstuvwxyz"
LATIN_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CYR_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
CYR_UPPER = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"


def _shift_alphabet(char: str, alphabet: str, shift: int) -> str:
    index = alphabet.find(char)
    if index == -1:
        return char
    new_index = (index + shift) % len(alphabet)
    return alphabet[new_index]


def caesar_cipher(text: str, shift: int) -> str:
    result_chars = []
    for ch in text:
        if ch in LATIN_LOWER:
            result_chars.append(_shift_alphabet(ch, LATIN_LOWER, shift))
        elif ch in LATIN_UPPER:
            result_chars.append(_shift_alphabet(ch, LATIN_UPPER, shift))
        elif ch in CYR_LOWER:
            result_chars.append(_shift_alphabet(ch, CYR_LOWER, shift))
        elif ch in CYR_UPPER:
            result_chars.append(_shift_alphabet(ch, CYR_UPPER, shift))
        else:
            result_chars.append(ch)
    return "".join(result_chars)


# Асимметричный «под капотом»: учебный RSA на фиксированных ключах
RSA_N = 3233  # 61 * 53
RSA_E = 17
RSA_D = 2753


def rsa_encrypt(plaintext: str) -> str:
    encoded_numbers = [str(pow(ord(ch), RSA_E, RSA_N)) for ch in plaintext]
    return " ".join(encoded_numbers)


def rsa_decrypt(cipher_numbers: str) -> str:
    parts = [p for p in cipher_numbers.strip().split() if p]
    try:
        decoded_chars = [chr(pow(int(p), RSA_D, RSA_N)) for p in parts]
    except Exception:
        return "Ошибка: ожидается набор целых чисел, разделённых пробелами"
    return "".join(decoded_chars)


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


# ================= Меню теории/тестов и дочерние окна =================
class TheoryTestsMenu(QWidget):
    def __init__(self, parent_window: QWidget):
        super().__init__()
        self.parent_window = parent_window
        self.setWindowTitle("Меню: теория и тесты")
        self.setGeometry(460, 260, 380, 280)

        root = QVBoxLayout()

        nav = QHBoxLayout()
        btn_back = QPushButton("← Назад")
        btn_back.clicked.connect(self.go_back)
        nav.addWidget(btn_back)
        nav.addStretch(1)
        root.addLayout(nav)

        btn_encrypt = QPushButton("Шифрование")
        btn_encrypt.clicked.connect(self.open_encrypt)
        root.addWidget(btn_encrypt)

        btn_decrypt = QPushButton("Расшифровка")
        btn_decrypt.clicked.connect(self.open_decrypt)
        root.addWidget(btn_decrypt)

        btn_test = QPushButton("Тест")
        btn_test.clicked.connect(self.open_test)
        root.addWidget(btn_test)

        btn_sym = QPushButton("Симметричные алгоритмы")
        btn_sym.clicked.connect(lambda: self.open_list("symmetric"))
        root.addWidget(btn_sym)

        btn_asym = QPushButton("Ассиметричные алгоритмы")
        btn_asym.clicked.connect(lambda: self.open_list("asymmetric"))
        root.addWidget(btn_asym)

        self.setLayout(root)

    def go_back(self):
        self.close()
        self.parent_window.show()

    def open_list(self, category: str):
        self.child = AlgorithmListWindow(self, category)
        self.hide()
        self.child.show()

    def open_encrypt(self):
        self.child = EncryptDecryptWindow(self, mode="encrypt")
        self.hide()
        self.child.show()

    def open_decrypt(self):
        self.child = EncryptDecryptWindow(self, mode="decrypt")
        self.hide()
        self.child.show()

    def open_test(self):
        self.child = QuizWindow(self)
        self.hide()
        self.child.show()


class AlgorithmListWindow(QWidget):
    def __init__(self, parent_window: QWidget, category: str):
        super().__init__()
        self.parent_window = parent_window
        self.category = category  # 'symmetric' | 'asymmetric'
        self.setWindowTitle("Симметричные алгоритмы" if category == "symmetric" else "Ассиметричные алгоритмы")
        self.setGeometry(460, 260, 420, 320)

        root = QVBoxLayout()

        nav = QHBoxLayout()
        btn_back = QPushButton("← Назад")
        btn_back.clicked.connect(self.go_back)
        nav.addWidget(btn_back)
        nav.addStretch(1)
        root.addLayout(nav)

        algos = SYMMETRIC_ALGOS if category == "symmetric" else ASYMMETRIC_ALGOS
        for name in algos:
            b = QPushButton(name)
            b.clicked.connect(lambda _=False, n=name: self.open_theory(n))
            root.addWidget(b)

        self.setLayout(root)

    def go_back(self):
        self.close()
        self.parent_window.show()

    def open_theory(self, algo_name: str):
        self.child = TheoryWindow(self, self.category, algo_name)
        self.hide()
        self.child.show()


class TheoryWindow(QWidget):
    def __init__(self, parent_window: QWidget, category: str, algo_name: str):
        super().__init__()
        self.parent_window = parent_window
        self.setWindowTitle(f"Теория: {algo_name}")
        self.setGeometry(460, 260, 560, 420)

        root = QVBoxLayout()

        nav = QHBoxLayout()
        btn_back = QPushButton("← Назад")
        btn_back.clicked.connect(self.go_back)
        nav.addWidget(btn_back)
        nav.addStretch(1)
        root.addLayout(nav)

        text = THEORY_TEXT.get("symmetric" if category == "symmetric" else "asymmetric", {}).get(algo_name, "")
        view = QTextEdit()
        view.setReadOnly(True)
        view.setPlainText(text)
        root.addWidget(view)

        self.setLayout(root)

    def go_back(self):
        self.close()
        self.parent_window.show()


class EncryptDecryptWindow(QWidget):
    def __init__(self, parent_window: QWidget, mode: str):
        super().__init__()
        self.parent_window = parent_window
        self.mode = mode  # 'encrypt' | 'decrypt'
        self.setWindowTitle("Шифрование" if mode == "encrypt" else "Расшифровка")
        self.setGeometry(460, 260, 560, 360)

        self.root = QVBoxLayout()

        nav = QHBoxLayout()
        btn_back = QPushButton("← Назад")
        btn_back.clicked.connect(self.go_back)
        nav.addWidget(btn_back)
        nav.addStretch(1)
        self.root.addLayout(nav)

        choice_box = QGroupBox("Выберите тип алгоритма")
        choice_layout = QHBoxLayout()
        btn_sym = QPushButton("Симметричный")
        btn_asym = QPushButton("Ассиметричный")
        btn_sym.clicked.connect(self.show_symmetric_form)
        btn_asym.clicked.connect(self.show_asymmetric_form)
        choice_layout.addWidget(btn_sym)
        choice_layout.addWidget(btn_asym)
        choice_box.setLayout(choice_layout)
        self.root.addWidget(choice_box)

        self.form_area = QVBoxLayout()
        self.root.addLayout(self.form_area)
        self.setLayout(self.root)

        # Храним ссылки на элементы формы
        self.input_line = None  # type: QLineEdit
        self.result_view = None  # type: QTextEdit
        self.hint_label = None  # type: QLabel

    def _clear_form(self):
        while self.form_area.count():
            item = self.form_area.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def show_symmetric_form(self):
        self._clear_form()
        mode_title = "Зашифровать" if self.mode == "encrypt" else "Расшифровать"

        self.form_area.addWidget(QLabel("Симметричный алгоритм: Цезарь (сдвиг 3)"))
        self.form_area.addWidget(QLabel("Введите текст:"))
        self.input_line = QLineEdit()
        self.form_area.addWidget(self.input_line)

        run_btn = QPushButton(mode_title)
        run_btn.clicked.connect(self._run_symmetric)
        self.form_area.addWidget(run_btn)

        self.result_view = QTextEdit()
        self.result_view.setReadOnly(True)
        self.form_area.addWidget(QLabel("Результат:"))
        self.form_area.addWidget(self.result_view)

    def _run_symmetric(self):
        if not self.input_line or not self.result_view:
            return
        text = self.input_line.text()
        if self.mode == "encrypt":
            out = caesar_cipher(text, 3)
        else:
            out = caesar_cipher(text, -3)
        self.result_view.setPlainText(out)

    def show_asymmetric_form(self):
        self._clear_form()
        mode_title = "Зашифровать" if self.mode == "encrypt" else "Расшифровать"

        self.form_area.addWidget(QLabel("Асимметричный алгоритм: RSA (учебный)"))
        if self.mode == "decrypt":
            self.hint_label = QLabel("Для RSA введите числа через пробел")
            self.form_area.addWidget(self.hint_label)
        self.form_area.addWidget(QLabel("Введите данные:"))

        self.input_line = QLineEdit()
        if self.mode == "decrypt":
            self.input_line.setPlaceholderText("Например: 2790 1313 1961 …")
        self.form_area.addWidget(self.input_line)

        run_btn = QPushButton(mode_title)
        run_btn.clicked.connect(self._run_asymmetric)
        self.form_area.addWidget(run_btn)

        self.result_view = QTextEdit()
        self.result_view.setReadOnly(True)
        self.form_area.addWidget(QLabel("Результат:"))
        self.form_area.addWidget(self.result_view)

    def _run_asymmetric(self):
        if not self.input_line or not self.result_view:
            return
        data = self.input_line.text()
        if self.mode == "encrypt":
            out = rsa_encrypt(data)
        else:
            out = rsa_decrypt(data)
        self.result_view.setPlainText(out)

    def go_back(self):
        self.close()
        self.parent_window.show()


class QuizWindow(QWidget):
    def __init__(self, parent_window: QWidget):
        super().__init__()
        self.parent_window = parent_window
        self.setWindowTitle("Тест по теории")
        self.setGeometry(460, 260, 640, 520)

        self.questions = [
            {
                "q": "К какому типу относится AES?",
                "options": ["Симметричному", "Асимметричному", "Это протокол обмена ключами"],
                "answer": 0,
            },
            {
                "q": "К какому типу относится RSA?",
                "options": ["Симметричному", "Асимметричному", "Потоковому"],
                "answer": 1,
            },
            {
                "q": "Что верно для симметричных алгоритмов?",
                "options": [
                    "Используют пару разных ключей",
                    "Один и тот же ключ для шифрования и расшифровки",
                    "Ключ вообще не нужен",
                ],
                "answer": 1,
            },
            {
                "q": "Для чего применяют Diffie–Hellman?",
                "options": ["Шифрование файла", "Подписание", "Согласование общего ключа"],
                "answer": 2,
            },
            {
                "q": "Какой алгоритм симметричный?",
                "options": ["DES", "RSA", "DSA"],
                "answer": 0,
            },
            {
                "q": "Что характеризует асимметричные алгоритмы?",
                "options": [
                    "Скорость выше, чем у симметричных",
                    "Нужна пара публичный/приватный ключ",
                    "Работают без математики",
                ],
                "answer": 1,
            },
        ]

        self.root = QVBoxLayout()

        nav = QHBoxLayout()
        btn_back = QPushButton("← Назад")
        btn_back.clicked.connect(self.go_back)
        nav.addWidget(btn_back)
        nav.addStretch(1)
        self.root.addLayout(nav)

        self.groups = []  # type: list

        for idx, q in enumerate(self.questions):
            box = QGroupBox(f"Вопрос {idx + 1}")
            v = QVBoxLayout()
            v.addWidget(QLabel(q["q"]))
            group = QButtonGroup(self)
            for opt_idx, opt in enumerate(q["options"]):
                rb = QRadioButton(opt)
                group.addButton(rb, opt_idx)
                v.addWidget(rb)
            box.setLayout(v)
            self.root.addWidget(box)
            self.groups.append(group)

        btn_check = QPushButton("Проверить")
        btn_check.clicked.connect(self.check_answers)
        self.root.addWidget(btn_check)

        self.result_label = QLabel("")
        self.root.addWidget(self.result_label)

        self.setLayout(self.root)

    def check_answers(self):
        score = 0
        for group, q in zip(self.groups, self.questions):
            checked_id = group.checkedId()
            if checked_id == q["answer"]:
                score += 1
        total = len(self.questions)
        self.result_label.setText(f"Результат: {score} из {total}")

    def go_back(self):
        self.close()
        self.parent_window.show()


# ================= Меню пользователя =================
class UserMenu(QWidget):
    def __init__(self, user):
        super().__init__()
        self.user = user
        self.setWindowTitle(f"Меню пользователя: {user.username}")
        self.setGeometry(500, 300, 320, 260)

        layout = QVBoxLayout()

        btn_change = QPushButton("Сменить пароль")
        btn_change.clicked.connect(self.change_password)
        layout.addWidget(btn_change)

        btn_rules = QPushButton("Показать требования к паролю")
        btn_rules.clicked.connect(self.show_rules)
        layout.addWidget(btn_rules)

        btn_theory_tests = QPushButton("Меню теории и тестов")
        btn_theory_tests.clicked.connect(self.open_theory_tests_menu)
        layout.addWidget(btn_theory_tests)

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

    def open_theory_tests_menu(self):
        self.child = TheoryTestsMenu(self)
        self.hide()
        self.child.show()

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
