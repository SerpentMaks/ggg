import sys
import os
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLineEdit, QPushButton, QLabel,
    QVBoxLayout, QHBoxLayout, QMessageBox, QInputDialog, QTextEdit,
    QGroupBox, QRadioButton, QButtonGroup, QComboBox, QSpinBox, QFormLayout
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
    "XOR",
]

ASYMMETRIC_ALGOS = [
    "RSA",
    "ElGamal",
    "Diffie–Hellman",
]

THEORY_TEXT = {
    "symmetric": {
        "Цезарь": (
            "Шифр Цезаря — моноалфавитная замена: каждую букву сдвигают на N позиций по кругу.\n"
            "• Ключ: целое число N (может быть отрицательным)\n"
            "• Алфавиты: поддерживаются латиница и кириллица, регистр сохраняется\n"
            "• Стойкость: низкая (защит от перебора 26/33 сдвигов нет)\n"
            "Пример: сдвиг 3 → HELLO → KHOOR; ПРИВЕТ → ТУЛЕЗХ"
        ),
        "Виженер": (
            "Шифр Виженера — полиалфавитная замена: сдвиг каждой буквы зависит от буквы ключа.\n"
            "• Ключ: слово/фраза (буквы), ключ повторяется по длине текста\n"
            "• Алфавиты: латиница и кириллица, регистр сохраняется\n"
            "• Стойкость: выше Цезаря, но уязвим при коротких ключах\n"
            "Пример: Текст=ATTACKATDAWN, Ключ=LEMON → Шифр=LXFOPVEFRNHR"
        ),
        "XOR": (
            "Потоковое шифрование XOR: каждый байт текста складывается по модулю 2 с байтом ключа.\n"
            "• Ключ: произвольная строка (повторяется по длине сообщения)\n"
            "• Результат: для удобства выводится в hex; для расшифровки подайте тот же ключ и hex\n"
            "• Стойкость: зависит от секретности и длины ключа; одноразовый блокнот (ключ=длина сообщения) — идеален\n"
            "Пример: Текст=HELLO, Ключ=KEY → Шифр=1d0a0f07... (hex)"
        ),
    },
    "asymmetric": {
        "RSA": (
            "RSA — шифрование на больших модулях n=p·q. Пара ключей: публичный (e,n), приватный (d,n).\n"
            "• Шифрование: C = M^e mod n; Расшифровка: M = C^d mod n\n"
            "• На практике M — это блок байтов после выравнивания/паддинга (OAEP), здесь — учебная версия посимвольно\n"
            "Пример (учебный): p=61, q=53, n=3233, e=17, d=2753; 'A'(65) → 2790 → 65"
        ),
        "ElGamal": (
            "ElGamal над Z_p*: публичные параметры (p — простое, g — порождающий), ключи: приватный x, публичный y=g^x mod p.\n"
            "• Шифрование символа m: выбираем случайный k; c1=g^k mod p, c2=m·y^k mod p\n"
            "• Расшифровка: m=c2·(c1^(p-1-x)) mod p\n"
            "• Важно: ord(символ) < p\n"
            "Пример: p=23, g=5, x=6 → y=8; m=10 → (c1,c2)=(19,2)"
        ),
        "Diffie–Hellman": (
            "Диффи–Хеллман — согласование общего секрета K без передачи его напрямую.\n"
            "• Параметры: p — простое, g — основание; стороны выбирают приватные a и b\n"
            "• Публичные: A=g^a mod p, B=g^b mod p; общий секрет: K=B^a=A^b mod p\n"
            "• В этой программе K используется как ключ для XOR (шифр в hex)\n"
            "Пример: p=23, g=5, a=6, B=19 → K=2 → используется как ключ"
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

# ================= Дополнительные алгоритмы (параметризуемые) =================
import secrets
import hashlib


def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    if not key:
        return text
    result_chars = []
    key_len = len(key)
    key_index = 0

    def get_shift_from_key_char(kch: str, alphabet: str) -> int:
        # try same case
        pos = alphabet.find(kch)
        if pos != -1:
            return pos
        # try lower-cased
        pos = alphabet.find(kch.lower())
        if pos != -1:
            return pos
        # try upper-cased
        pos = alphabet.find(kch.upper())
        if pos != -1:
            return pos
        return 0

    for ch in text:
        if ch in LATIN_LOWER:
            kch = key[key_index % key_len]
            shift = get_shift_from_key_char(kch, LATIN_LOWER)
            result_chars.append(_shift_alphabet(ch, LATIN_LOWER, -shift if decrypt else shift))
            key_index += 1
        elif ch in LATIN_UPPER:
            kch = key[key_index % key_len]
            shift = get_shift_from_key_char(kch, LATIN_UPPER)
            result_chars.append(_shift_alphabet(ch, LATIN_UPPER, -shift if decrypt else shift))
            key_index += 1
        elif ch in CYR_LOWER:
            kch = key[key_index % key_len]
            shift = get_shift_from_key_char(kch, CYR_LOWER)
            result_chars.append(_shift_alphabet(ch, CYR_LOWER, -shift if decrypt else shift))
            key_index += 1
        elif ch in CYR_UPPER:
            kch = key[key_index % key_len]
            shift = get_shift_from_key_char(kch, CYR_UPPER)
            result_chars.append(_shift_alphabet(ch, CYR_UPPER, -shift if decrypt else shift))
            key_index += 1
        else:
            result_chars.append(ch)
    return "".join(result_chars)


def xor_encrypt_to_hex(text: str, key: str) -> str:
    if not key:
        return text
    tb = text.encode("utf-8")
    kb = key.encode("utf-8")
    out = bytearray()
    for i, b in enumerate(tb):
        out.append(b ^ kb[i % len(kb)])
    return out.hex()


def xor_decrypt_from_hex(hex_text: str, key: str) -> str:
    if not key:
        return hex_text
    try:
        cb = bytes.fromhex(hex_text.strip())
    except ValueError:
        return "Ошибка: ожидается hex-строка (0-9a-f)"
    kb = key.encode("utf-8")
    out = bytearray()
    for i, b in enumerate(cb):
        out.append(b ^ kb[i % len(kb)])
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return out.decode("utf-8", errors="replace")


def rsa_encrypt_with_key(plaintext: str, e: int, n: int) -> str:
    return " ".join(str(pow(ord(ch), e, n)) for ch in plaintext)


def rsa_decrypt_with_key(cipher_numbers: str, d: int, n: int) -> str:
    parts = [p for p in cipher_numbers.strip().split() if p]
    try:
        decoded_chars = [chr(pow(int(p), d, n)) for p in parts]
    except Exception:
        return "Ошибка: ожидается набор целых чисел, разделённых пробелами"
    return "".join(decoded_chars)


def elgamal_encrypt_text(plaintext: str, p: int, g: int, y: int) -> str:
    if p <= 2:
        return "Ошибка: p должно быть простым > 2"
    pairs = []
    for ch in plaintext:
        m = ord(ch)
        if m >= p:
            return "Ошибка: ord(символа) >= p. Выберите большее p."
        k = secrets.randbelow(p - 2) + 1  # 1..p-2
        c1 = pow(g, k, p)
        s = pow(y, k, p)
        c2 = (m * s) % p
        pairs.append(f"{c1},{c2}")
    return " ".join(pairs)


def elgamal_decrypt_text(cipher_pairs: str, p: int, x: int) -> str:
    parts = [p for p in cipher_pairs.replace(";", " ").split() if p]
    out_chars = []
    try:
        for pair in parts:
            c1_str, c2_str = pair.split(",")
            c1, c2 = int(c1_str), int(c2_str)
            s_inv = pow(c1, p - 1 - x, p)
            m = (c2 * s_inv) % p
            out_chars.append(chr(m))
    except Exception:
        return "Ошибка: ожидаются пары вида c1,c2, разделённые пробелами"
    return "".join(out_chars)


def _dh_shared_key_bytes(p: int, g: int, a: int, B: int) -> bytes:
    K = pow(B, a, p)
    # Деривируем байты ключа из числа K через SHA-256
    digest = hashlib.sha256(str(K).encode("utf-8")).digest()
    return digest


def dh_xor_encrypt_text(plaintext: str, p: int, g: int, a: int, B: int) -> str:
    key_bytes = _dh_shared_key_bytes(p, g, a, B)
    tb = plaintext.encode("utf-8")
    out = bytearray()
    for i, b in enumerate(tb):
        out.append(b ^ key_bytes[i % len(key_bytes)])
    return out.hex()


def dh_xor_decrypt_text(hex_cipher: str, p: int, g: int, a: int, B: int) -> str:
    try:
        cb = bytes.fromhex(hex_cipher.strip())
    except ValueError:
        return "Ошибка: ожидается hex-строка (0-9a-f)"
    key_bytes = _dh_shared_key_bytes(p, g, a, B)
    out = bytearray()
    for i, b in enumerate(cb):
        out.append(b ^ key_bytes[i % len(key_bytes)])
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return out.decode("utf-8", errors="replace")


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

        # Добавим мини-примеры использования для закрепления
        base_text = THEORY_TEXT.get("symmetric" if category == "symmetric" else "asymmetric", {}).get(algo_name, "")
        extras = []
        if algo_name == "Цезарь":
            extras.append("Пример ввода: текст='Привет', сдвиг=5 → 'Фхнёзч'")
        if algo_name == "Виженер":
            extras.append("Пример: текст='АТАКА', ключ='ЛИМОН' → шифр")
        if algo_name == "XOR":
            extras.append("Пример: текст='HELLO', ключ='KEY' → hex-шифр")
        if algo_name == "RSA":
            extras.append("В этой программе можно ввести e и n (для шифрования) или d и n (для расшифровки)")
        if algo_name == "ElGamal":
            extras.append("Вводите p,g,y для шифрования и p,x для расшифровки; пары вида c1,c2")
        if algo_name == "Diffie–Hellman":
            extras.append("Будет выведен/ожидается hex, ключ выводится из общего секрета")
        text = base_text + ("\n\n" + "\n".join(extras) if extras else "")
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
        self.setGeometry(460, 260, 640, 520)

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
        self.algo_combo = None  # type: QComboBox
        self.param_box = None   # type: QGroupBox
        self.param_form = None  # type: QFormLayout
        self.param_widgets = {} # name -> widget

    def _clear_form(self):
        while self.form_area.count():
            item = self.form_area.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def show_symmetric_form(self):
        self._clear_form()
        mode_title = "Зашифровать" if self.mode == "encrypt" else "Расшифровать"

        # Выбор алгоритма
        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Симметричный алгоритм:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(SYMMETRIC_ALGOS)
        self.algo_combo.currentTextChanged.connect(self._rebuild_symmetric_params)
        algo_row.addWidget(self.algo_combo)
        self.form_area.addLayout(algo_row)

        # Параметры
        self.param_box = QGroupBox("Параметры")
        self.param_form = QFormLayout()
        self.param_box.setLayout(self.param_form)
        self.form_area.addWidget(self.param_box)
        self.param_widgets = {}
        self._rebuild_symmetric_params(self.algo_combo.currentText())

        # Ввод данных
        self.form_area.addWidget(QLabel("Введите текст:" if self.mode == "encrypt" else "Введите данные:"))
        self.input_line = QLineEdit()
        self.form_area.addWidget(self.input_line)

        # Кнопка запуска
        run_btn = QPushButton(mode_title)
        run_btn.clicked.connect(self._run_symmetric)
        self.form_area.addWidget(run_btn)

        # Результат
        self.result_view = QTextEdit()
        self.result_view.setReadOnly(True)
        self.form_area.addWidget(QLabel("Результат:"))
        self.form_area.addWidget(self.result_view)

    def _run_symmetric(self):
        if not self.input_line or not self.result_view or not self.algo_combo:
            return
        algo = self.algo_combo.currentText()
        text = self.input_line.text()
        try:
            if algo == "Цезарь":
                shift_widget = self.param_widgets.get("shift")
                shift = int(shift_widget.value()) if shift_widget else 3
                out = caesar_cipher(text, shift if self.mode == "encrypt" else -shift)
            elif algo == "Виженер":
                key_widget = self.param_widgets.get("key")
                key = key_widget.text() if key_widget else ""
                out = vigenere_cipher(text, key, decrypt=(self.mode == "decrypt"))
            elif algo == "XOR":
                key_widget = self.param_widgets.get("key")
                key = key_widget.text() if key_widget else ""
                if self.mode == "encrypt":
                    out = xor_encrypt_to_hex(text, key)
                else:
                    out = xor_decrypt_from_hex(text.strip(), key)
            else:
                out = "Неизвестный алгоритм"
        except Exception as exc:
            out = f"Ошибка: {exc}"
        self.result_view.setPlainText(out)

    def show_asymmetric_form(self):
        self._clear_form()
        mode_title = "Зашифровать" if self.mode == "encrypt" else "Расшифровать"

        # Выбор алгоритма
        algo_row = QHBoxLayout()
        algo_row.addWidget(QLabel("Асимметричный алгоритм:"))
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(ASYMMETRIC_ALGOS)
        self.algo_combo.currentTextChanged.connect(self._rebuild_asymmetric_params)
        algo_row.addWidget(self.algo_combo)
        self.form_area.addLayout(algo_row)

        # Параметры
        self.param_box = QGroupBox("Параметры")
        self.param_form = QFormLayout()
        self.param_box.setLayout(self.param_form)
        self.form_area.addWidget(self.param_box)
        self.param_widgets = {}
        self._rebuild_asymmetric_params(self.algo_combo.currentText())

        # Ввод данных
        self.form_area.addWidget(QLabel("Введите данные:"))
        self.input_line = QLineEdit()
        if self.mode == "decrypt" and self.algo_combo.currentText() == "RSA":
            self.input_line.setPlaceholderText("Например: 2790 1313 1961 …")
        self.form_area.addWidget(self.input_line)

        # Кнопка запуска
        run_btn = QPushButton(mode_title)
        run_btn.clicked.connect(self._run_asymmetric)
        self.form_area.addWidget(run_btn)

        # Результат
        self.result_view = QTextEdit()
        self.result_view.setReadOnly(True)
        self.form_area.addWidget(QLabel("Результат:"))
        self.form_area.addWidget(self.result_view)

    def _run_asymmetric(self):
        if not self.input_line or not self.result_view or not self.algo_combo:
            return
        data = self.input_line.text()
        algo = self.algo_combo.currentText()
        try:
            if algo == "RSA":
                if self.mode == "encrypt":
                    e = int(self.param_widgets.get("e").value())
                    n = int(self.param_widgets.get("n").text())
                    out = rsa_encrypt_with_key(data, e, n)
                else:
                    d = int(self.param_widgets.get("d").value())
                    n = int(self.param_widgets.get("n").text())
                    out = rsa_decrypt_with_key(data, d, n)
            elif algo == "ElGamal":
                if self.mode == "encrypt":
                    p = int(self.param_widgets.get("p").text())
                    g = int(self.param_widgets.get("g").text())
                    y = int(self.param_widgets.get("y").text())
                    out = elgamal_encrypt_text(data, p, g, y)
                else:
                    p = int(self.param_widgets.get("p").text())
                    x = int(self.param_widgets.get("x").text())
                    out = elgamal_decrypt_text(data, p, x)
            elif algo == "Diffie–Hellman":
                p = int(self.param_widgets.get("p").text())
                g = int(self.param_widgets.get("g").text())
                a = int(self.param_widgets.get("a").text())
                B = int(self.param_widgets.get("B").text())
                if self.mode == "encrypt":
                    out = dh_xor_encrypt_text(data, p, g, a, B)
                else:
                    out = dh_xor_decrypt_text(data, p, g, a, B)
            else:
                out = "Неизвестный алгоритм"
        except Exception as exc:
            out = f"Ошибка: {exc}"
        self.result_view.setPlainText(out)

    def go_back(self):
        self.close()
        self.parent_window.show()

    # ---------- helpers ----------
    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _rebuild_symmetric_params(self, algo_name: str):
        if not self.param_form:
            return
        # clear
        self.param_widgets = {}
        self._clear_layout(self.param_form)

        if algo_name == "Цезарь":
            shift = QSpinBox()
            shift.setRange(-10000, 10000)
            shift.setValue(3)
            self.param_widgets["shift"] = shift
            self.param_form.addRow("Сдвиг:", shift)
        elif algo_name == "Виженер":
            key = QLineEdit()
            key.setPlaceholderText("Ключевое слово, например LEMON")
            self.param_widgets["key"] = key
            self.param_form.addRow("Ключ:", key)
        elif algo_name == "XOR":
            key = QLineEdit()
            key.setPlaceholderText("Строка-ключ, повторяется по длине сообщения")
            self.param_widgets["key"] = key
            self.param_form.addRow("Ключ:", key)
        # hints
        if self.hint_label:
            self.hint_label.deleteLater()
            self.hint_label = None
        if algo_name == "XOR" and self.mode == "decrypt":
            self.hint_label = QLabel("Введите hex-строку шифра")
            self.form_area.insertWidget(3, self.hint_label)  # after params

    def _rebuild_asymmetric_params(self, algo_name: str):
        if not self.param_form:
            return
        # clear
        self.param_widgets = {}
        self._clear_layout(self.param_form)

        if algo_name == "RSA":
            if self.mode == "encrypt":
                e = QSpinBox(); e.setRange(3, 1_000_000_000); e.setValue(17)
                n = QLineEdit(); n.setText(str(RSA_N))
                self.param_widgets["e"] = e
                self.param_widgets["n"] = n
                self.param_form.addRow("e:", e)
                self.param_form.addRow("n:", n)
            else:
                d = QSpinBox(); d.setRange(3, 10_000_000_000); d.setValue(RSA_D)
                n = QLineEdit(); n.setText(str(RSA_N))
                self.param_widgets["d"] = d
                self.param_widgets["n"] = n
                self.param_form.addRow("d:", d)
                self.param_form.addRow("n:", n)
            # hints
            if self.hint_label:
                self.hint_label.deleteLater()
                self.hint_label = None
            if self.mode == "decrypt":
                self.hint_label = QLabel("Введите числа шифртекста через пробел (например: 2790 1313 …)")
                self.form_area.insertWidget(3, self.hint_label)
        elif algo_name == "ElGamal":
            p = QLineEdit(); p.setText("23")
            if self.mode == "encrypt":
                g = QLineEdit(); g.setText("5")
                y = QLineEdit(); y.setText("8")
                self.param_widgets["p"] = p
                self.param_widgets["g"] = g
                self.param_widgets["y"] = y
                self.param_form.addRow("p:", p)
                self.param_form.addRow("g:", g)
                self.param_form.addRow("y (публичный):", y)
            else:
                x = QLineEdit(); x.setText("6")
                self.param_widgets["p"] = p
                self.param_widgets["x"] = x
                self.param_form.addRow("p:", p)
                self.param_form.addRow("x (приватный):", x)
            if self.hint_label:
                self.hint_label.deleteLater()
                self.hint_label = None
            if self.mode == "decrypt":
                self.hint_label = QLabel("Введите пары c1,c2 через пробел (пример: 19,2 7,15 …)")
                self.form_area.insertWidget(3, self.hint_label)
        elif algo_name == "Diffie–Hellman":
            p = QLineEdit(); p.setText("23")
            g = QLineEdit(); g.setText("5")
            a = QLineEdit(); a.setText("6")
            B = QLineEdit(); B.setText("19")
            self.param_widgets["p"] = p
            self.param_widgets["g"] = g
            self.param_widgets["a"] = a
            self.param_widgets["B"] = B
            self.param_form.addRow("p:", p)
            self.param_form.addRow("g:", g)
            self.param_form.addRow("a (ваш приватный):", a)
            self.param_form.addRow("B (чужой публичный):", B)
            if self.hint_label:
                self.hint_label.deleteLater()
                self.hint_label = None
            hint_text = "Вводите обычный текст. Результат/ввод шифра — hex."
            self.hint_label = QLabel(hint_text)
            self.form_area.insertWidget(3, self.hint_label)


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
            {
                "q": "В шифре Цезаря сдвиг - это…",
                "options": ["Размер блока", "Количество позиций, на которое смещается буква", "Генератор простых чисел"],
                "answer": 1,
            },
            {
                "q": "В Виженере сдвиг определяется…",
                "options": ["Буквой ключа", "Номером строки", "Никак"],
                "answer": 0,
            },
            {
                "q": "Что верно про XOR-шифрование?",
                "options": ["Шифр и расшифровка одинаковые операции", "Нужен открытый модуль n", "Использует кривые"],
                "answer": 0,
            },
            {
                "q": "DH (Диффи–Хеллман) используется для…",
                "options": ["Подписи", "Согласования общего секрета", "Сжатия"],
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
        wrong = []
        for idx, (group, q) in enumerate(zip(self.groups, self.questions), start=1):
            checked_id = group.checkedId()
            if checked_id == q["answer"]:
                score += 1
            else:
                wrong.append(idx)
        total = len(self.questions)
        detail = "" if not wrong else f". Ошибки в вопросах: {', '.join(map(str, wrong))}"
        self.result_label.setText(f"Результат: {score} из {total}{detail}")

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
