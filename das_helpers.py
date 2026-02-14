"""helper function for DAS"""
import hashlib
import re
import secrets
import hmac
import requests


def hash_password(password: str) -> str:
    """
    Docstring для hash_password

    :param password: password you want to hash
    :type password: str
    :return: hash
    :rtype: str
    """
    salt = secrets.token_bytes(16)  # random salt
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,  # iterations (slow = good)
    )
    return salt.hex() + ":" + key.hex()


class Exit(Exception):
    """
    Docstring для Exit
    general class for user exceptions and das errors
    """

    def __init__(self, value, name):
        super().__init__(value)
        self.name = name


def verify_password(password: str, stored: str) -> bool:
    """
    Docstring для verify_password

    :param password: password you want to check
    :type password: str
    :param stored: stored hash:salt
    :type stored: str
    :return: do passwords match
    :rtype: bool
    """
    salt_hex, key_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    stored_key = bytes.fromhex(key_hex)

    new_key = hashlib.pbkdf2_hmac("sha256",
                                  password.encode("utf-8"),
                                  salt,
                                  200_000)
    return hmac.compare_digest(new_key, stored_key)


class LRUDict:
    """
    Docstring для LRUDict

    it's a dict which is removing items by LRU
    """

    __slots__ = ("capacity", "cache", "__list")

    def __init__(self, capacity=1024):
        self.cache = {}
        self.capacity = capacity

    def __getitem__(self, key):
        """
        Docstring для __getitem__

        :param self: dict itself
        :param key: key for the item
        """
        if key not in self.cache:
            return None
        # Move to end (Most Recently Used)
        val = self.cache.pop(key)
        self.cache[key] = val
        return val

    def get(self, key):
        """
        Docstring для get

        :param self: dict itself
        :param key: key for the item
        """
        return self[key]

    def __setitem__(self, key, value=None):
        """
        Docstring для __setitem__

        :param self: dict itself
        :param key: key for the item
        """
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) >= self.capacity:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        self.cache[key] = value

    def put(self, key, value):
        """
        sets key's value to value
        Docstring для put

        :param self: dict itself
        :param key: key for the item
        :param value: value to use
        """
        self[key] = value

    def setdefault(self, key, default_value=None):
        """
        sets key's value to value if there is no such key in the dict
        Docstring для put

        :param self: dict itself
        :param key: key for the item
        :param value: value to use
        """
        if key in self.cache:
            return self[key]
        self[key] = default_value
        return default_value

    def __str__(self):
        return str(self.cache)


def split_by_not_strings(text, sep="{"):
    """
    Docstring для split_by_not_strings
    
    :param text: text which to split
    :param sep: separator by which to split
    """
    in_string = False
    escape = False
    part = ""
    for i in text:
        if i == '"' and not escape:
            in_string = not in_string
        escape = False
        if i == "\\":
            escape = not escape
        if not in_string and i == sep:
            yield part
            part = ""
        part += i
    yield part


def split_by_not_in_blocks(text: str, sep: str = ";"):
    """
    Split `text` by `sep` but ignore separators inside:
      - single or double quotes
      - curly blocks `{ ... }` outside quotes
    Handles escaped quotes and separators.
    """
    result = []
    buf = []
    depth = 0
    in_quote = None
    escape = False

    for c in text:
        if escape:
            buf.append(c)
            escape = False
            continue

        if c == "\\":
            buf.append(c)
            escape = True
            continue

        # start or end quote
        if in_quote:
            buf.append(c)
            if c == in_quote:
                in_quote = None
            continue
        elif c in ("'", '"'):
            buf.append(c)
            in_quote = c
            continue

        # handle blocks only outside quotes
        if c == "{" and not in_quote:
            depth += 1
            buf.append(c)
            continue
        if c == "}" and not in_quote:
            depth -= 1
            buf.append(c)
            continue

        # split only if outside quotes and blocks
        if c == sep and depth == 0 and not in_quote:
            result.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)

    if buf:
        result.append("".join(buf).strip())

    return result


def split_block(code: str):
    """
    Splits a line into head + top-level blocks.
    Handles nested braces, quoted braces, and multiple top-level blocks.
    """
    code = code.strip()
    head_chars = []
    blocks = []

    depth = 0
    in_string = False
    escape = False
    current_block = []

    for ch in code:
        if ch == "\\" and not escape:
            escape = True
            if depth == 0:
                head_chars.append(ch)
            else:
                current_block.append(ch)
            continue

        if ch == '"' and not escape:
            in_string = not in_string

        escape = False

        if ch == "{" and not in_string:
            if depth == 0:
                # start of a top-level block
                current_block = []
            else:
                current_block.append(ch)
            depth += 1
            continue
        elif ch == "}" and not in_string:
            depth -= 1
            if depth == 0:
                blocks.append("".join(current_block).strip())
                current_block = []
                continue
            else:
                current_block.append(ch)
                continue

        if depth == 0:
            head_chars.append(ch)
        else:
            current_block.append(ch)

    head = "".join(head_chars).strip()
    return [head] + blocks


def split_iter(text, seps=('"',)):
    """
    Splits text by any of the separators in seps, ignoring escaped separators.
    Escaped characters are handled:
    \n -> newline,
    \t -> tab,
    \\ -> backslash."""
    value = ""
    i = 0
    while i < len(text):
        if text[i] == "\\":
            for sep in seps:
                if text.startswith(sep, i + 1):
                    value += sep
                    i += 1 + len(sep)
                    break
            else:
                if i + 1 < len(text):
                    if text[i + 1] == "t":
                        value += "\t"
                    elif text[i + 1] == "n":
                        value += "\n"
                    elif text[i + 1] == "\\":
                        value += "\\"
                    else:
                        value += "\\" + text[i + 1]
                    i += 2
                # one character for \ one
                # for the escaped sequence so 2
                else:
                    value += "\\"  # lone trailing backslash
                    i += 1
            continue

        for sep in seps:
            if text.startswith(sep, i):
                yield value
                value = ""
                i += len(sep)
                break
        else:
            value += text[i]
            i += 1  # just a normal character
    yield value


def is_pwned(password: str) -> bool:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                       timeout=5)
    if res.status_code != 200:
        return False  # fail open, or handle differently

    return any(line.split(":")[0] == suffix for line in res.text.splitlines())


class Sandbox:
    """
    Docstring для Sandbox
    saves user data
    """

    __slots__ = (
        "ib",
        "ub",
        "_stack",
        "theme",
        "hist",
        "heap",
        "heap_next"
    )

    def __init__(self):
        self.ib = [""]
        self.ub = [""]
        self.hist = [""]
        self.heap = []          # list of blocks
        self.heap_next = 0      # next free address
        # Теперь это одна сплошная строка (str), а не кортеж
        self._stack = [{
            # --- System Boot & Entry Points ---
            "MyaOS": "txt/not existing... yet",
            # Подкаталог с документацией
            "sys/bin/docs/file.open": """txt/Команда:
/file.open "[имя]" "arg1" "arg2"...
Описание: Открывает и выполняет содержимое файла.
Аргументы используются fnc/ файлами как ${номкр_аргумента}.""",
            "sys/bin/docs/file.save": '''txt/Команда:
/file.save "[тип/путь]" "[контент]"
Описание: Сохраняет данные в файл.''',
            "sys/bin/docs/math.add": '''txt/Команда: /math.add "[n1]" "[n2]"
Описание: Складывает два числа.''',
            "sys/bin/docs/pointer": "txt/Символ: @\nОписание: Pointer Protector. Создает копию Sandbox для выполнения команды.",
            "sys/bin/docs/link": "txt/Символ: #\nОписание: Link. Быстрый вызов файла (синоним /file.open).",
            "sys/bin/enhelp": """txt/--- MyaOS Quick Ref ---
[SYNTAX] /cmd "arg1" "arg2"
[LINK]   #file      -> Run file (Alias: /file.open)
[PTR]    @#file     -> Run isolated (returns value)
[MANUAL] /docs      -> List topics
         /docs name -> Read topic (e.g., /docs math)
-----------------------""",
            "sys/bin/docs/core": """txt/=== CORE CONCEPTS ===

1. DATA TYPES (Prefixes):
   - int: Integers (int10, int-5)
   - flt: Floating point (flt3.14)
   - str: Strings (strHello World)
   - bit: Boolean (bit1=True, bit0=False)
   - jsn: JSON Objects/Lists (jsn["a","b"])
   - nth: Null/Limits (nthNone, nthinf, nth何, nthnan, nth-inf)
   * Auto-detection works, but prefixes enforce type.

2. POINTER PROTECTOR (@):
   Syntax: @#filename or @/command
   Effect: Creates a RAM snapshot, runs code, returns last result (ib[-1]).
   Usage: Use for getting values without polluting chat.
   Ex: /math.add 10 int@#my_calc_script

3. FILE HEADERS:
   - com/ : Command script (executes lines).
   - fnc/ : Function. Replaces ${0}, ${1}... with args.
   - txt/ : Plain text (read-only).
   - lst/ : List. Emits each line as a separate event.
   - var/ : Variable storage.
""",
            "sys/bin/docs/file": """txt/=== FILE I/O MODULE ===

/file.save "type/name" "content"
  > Creates/Overwrites file.
  > Ex: /file.save "fnc/sum" "/math.add ${0} ${1}"

/file.open "name" [args...]
  > Executes file. Shortcut: #name
  > For fnc/ files, args are injected into ${N}.

/file.delete "name"      -> Remove file.
/file.deleteall          -> WIPE ALL DATA (Caution!).
/file.ls "dir/"          -> List files in directory.
/file.copy "src" "dest"  -> Duplicate file.
/file.move "src" "dest"  -> Rename or move.
/file.text "name"        -> Print raw content.
""",
            "sys/bin/docs/enmath": """txt/=== MATH MODULE ===

ARITHMETIC:
  /math.add "a" "b"  -> a + b
  /math.sub "a" "b"  -> a - b
  /math.mul "a" "b"  -> a * b
  /math.div "a" "b"  -> a / b
  /math.pow "a" "b"  -> a ^ b (Power)

ADVANCED:
  /math.sum "a" "b" "c"... -> Sum all args.
  /math.gt  "a" "b"        -> Returns bit1 if a > b.
  /math.lt  "a" "b"        -> Returns bit1 if a < b.
  /math.eq  "a" "b"        -> Returns bit1 if a == b.

TRIGONOMETRY:
  .sin, .cos, .tan, .sinh, .cosh, .tanh
  Ex: /math.cos 3.14159
Use /echo "str@#\\"sys/bin/docs/команда_без_слэш\\"" for more info.
""",
            "sys/bin/docs/flow": """txt/=== CONTROL FLOW ===

/if "condition" /then "code_file" [/else "alt_file"]
  > Checks condition (bit1/true).
  > Supports ops: =, !=, >, < in args.
  > Ex: /if "int@#score" ">" 10 /then "win_script"

/for "var" in "count" "code_file"
  > Loops 'count' times.
  > Inject loop index via ${var} in the target file.
  > Ex: /for "i" in 5 "loop_body"

/try "primary" :fails: "fallback"
  > Tries running primary file. If error, runs fallback.
  > Ex: /try "risky_script" :fails: "safe_script"
""",
            "sys/bin/docs/data": """txt/=== DATA MANIPULATION ===

STRINGS:
  /str.upper "text"       -> TEXT
  /str.lower "TEXT"       -> text
  /str.replace "s" "o" "n"-> Replace 'o' with 'n' in 's'.
  /str.split "s" "sep"    -> Returns jsn["part1",...]

LISTS (JSON):
  /lst.get "list" "idx"   -> Get item at index/key.
  /lst.set "list" "idx" "val" -> Update item (returns new list).
  /lst.in  "val" "list"   -> Check existence (bit1/0).
  /lst.join "list" "sep"  -> Join list into string.
""",
            "sys/bin/docs/sys": """txt/=== SYSTEM & CANVAS ===

SYSTEM:
  /echo "text"          -> Print to console & history.
  /sys.addchat "text"   -> Add to history only (silent).
  /sys.wait "sec"       -> Pause execution.
  /sys.input "varname"  -> Wait for user input, save to file.
  /sys.theme "name"     -> Set UI theme (dark/light).

CANVAS (Drawing):
  /canvas.clear
  /canvas.line "from_xy" "to_xy" "color"
  /canvas.rect "rect_arr" "color"
  /canvas.text "xy" "text" "font" "color"
  > Coords are lists: jsn[0,0]
""",
            "sys/bin/help": """txt/
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  DAS Terminal v2.0 - Справочная система                 ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ #"filename"            - Запуск файла (Alias)           ┃
┃ /echo "@#\"filename\"" - Изолированный запуск (Pointer) ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛""",
            "sys/bin/docs/rules": """txt/=== БАЗОВЫЕ ПРАВИЛА ===
1. Синтаксис: /команда "арг1" "арг2".
2. Строки: Всегда используй кавычки для аргументов.
3. Экранирование: Используй \\" для кавычек внутри строк.
4. Переменные:
   - $name$"val" - быстрая запись в файл.
   - $name= "file" - записать результат выполнения файла в name.""",
            "sys/bin/docs/pointers": """txt/=== POINTER PROTECTOR (@) ===
Символ '@' создает клон Sandbox. Все изменения (ib, ub, файлы) внутри клона удаляются после выполнения, возвращая только результат.
Пример:
/math.add "5" "int@#\"calculate_bonus\""
Здесь #\"calculate_bonus\" выполнится "в уме", и его результат подставится в /math.add.""",
            "sys/bin/docs/links": """txt/=== LINKS (#) ===
Символ '#' — это короткий путь к /file.open.
#"my_script" "hello"  ==  /file.open "my_script" "hello"
Если файл имеет тип fnc/, аргументы подставятся в ${0}, ${1} и т.д.""",
            "sys/bin/docs/math": """txt/=== MATH MODULE ===
БАЗА: add, sub, mul, div, pow, mod (%), abs.
ТРИГОНОМЕТРИЯ: sin, cos, tan, sinh, cosh, tanh.
ПРОЧЕЕ:
- /math.comb "n" "k" : Сочетания.
- /math.sum "a" "b" "c"... : Сумма всех аргументов.
- /math.gt|lt|eq "a" "b" : Сравнение (возвращает bit1/0).""",
            "sys/bin/docs/o": """txt/=== OPERATOR "o" ===
Универсальный оператор для быстрых вычислений:
1 арг: o "val" op
   - ! (not), % (float percent), abs, ++/-- (inc/dec переменную),
        %?(возврашает bit1 с вероятностью val*100%)
   - "file exists" (проверка файла)
2 арга: o "A" op "B"
   - Сравнение: ==, === (с учетом типа), >, <, >=, <=, type is
   - Логика: &&, ||, ^
   - Массивы: in (наличие), + (слияние), - (разность)
   - Математика: +, -, *, /, %, //, **, <<, >>
   - Строки: starts with, ends with, ~ (regex)
3 арга: o "cond_pointer" ? "val1" :: "val2" (Тернарный оператор)""",
            "sys/bin/docs/lambda": """txt/=== LAMBDA & FILES ===
- /lambda "name" -> "code" : Быстрое создание функции.
- Типы файлов:
  - com/ : Функция - alias.
  - fnc/ : Функция с поддержкой ${0}.
  - lst/ : Список, элементы которого выводятся в ib по очереди.
  - var/ : Простое хранилище значения - переменная.""",
            "sys/bin/docs/tests": """txt/=== ТЕСТИРОВАНИЕ (TRY) ===
- /try "file" : Пробует запустить файл, игнорируя ошибки.
- /try "primary" :fails: "fallback" : Если primary упадет, запустится fallback.
Полезно для проверки наличия файлов или сетевых ответов.""",
        }]
        self.theme = "dark"

    @property
    def files(self):
        return self._stack[-1]

    @files.setter
    def files(self, value):
        self._stack[-1] = value

    def push_frame(self):
        self._stack.append(self.files.copy())

    def pop_frame(self):
        if len(self._stack) == 1:
            raise RuntimeError("cannot pop root frame")
        self._stack.pop()

    def __str__(self):
        return (f"[ib:{self.ib}ub:{self.ub}hist:{self.hist}"
                f"files:{self.files}theme:{self.theme}]")
        # ---------- HEAP ----------

    def malloc(self, size: int):
        # reuse free block
        for block in self.heap:
            if block["free"] and block["size"] >= size:
                block["free"] = False
                return block["addr"]

        # create new block
        addr = self.heap_next
        self.heap_next += size

        self.heap.append({
            "addr": addr,
            "size": size,
            "free": False,
            "data": [None] * size,
        })
        return addr

    def free(self, addr: int):
        """free dinamic"""
        for block in self.heap:
            if block["addr"] == addr:
                block["free"] = True
                block["data"] = [None] * block["size"]
                return True
        return False

    def heap_read(self, addr: int, index: int):
        """read from dynamic alloc memory"""
        for block in self.heap:
            if block["addr"] == addr and not block["free"]:
                if 0 <= index < block["size"]:
                    return block["data"][index]

    def heap_write(self, addr: int, index: int, value):
        """write to dynamic alloc memory"""
        for block in self.heap:
            if block["addr"] == addr and not block["free"]:
                if 0 <= index < block["size"]:
                    block["data"][index] = value
                    return


def eval_expr(expr: str):
    """
    Safe arithmetic expression evaluator
    supports + - * / ( )
    """

    tokens = re.findall(r"\d+\.\d+|//|\d+|[()+\-*/%\^\\]", expr)
    if not tokens:
        raise ValueError("Empty expression")

    prec = {"+": 1, "-": 1, "*": 2, "/": 2, "^": 3, "%": 2, "\\": 2, "//": 2}
    output = []
    ops = []

    def apply():
        try:
            b = output.pop()
            a = output.pop()
            op = ops.pop()
            if (
                isinstance(b, (int, float))
                and isinstance(b, (int, float))
                and isinstance(op, str)
            ):
                if op == "+":
                    output.append(a + b)
                elif op == "-":
                    output.append(a - b)
                elif op == "%":
                    output.append(a % b)
                elif op == "*":
                    output.append(a * b)
                elif op == "^":
                    output.append(a**b)
                elif op == "/":
                    output.append(a / b)
                elif op == "//":
                    output.append(a // b)
                elif op == "\\":
                    output.append(a // b)
        except (ZeroDivisionError, ValueError, TypeError) as e:
            print(repr(e))

    for t in tokens:
        if re.match(r"\d", t):
            output.append(float(t) if "." in t else int(t))
        elif t in prec:
            while ops and ops[-1] in prec and prec[ops[-1]] >= prec[t]:
                apply()
            ops.append(t)
        elif t == "(":
            ops.append(t)
        elif t == ")":
            while ops[-1] != "(":
                apply()
            ops.pop()

    while ops:
        apply()

    return output[0]


class Value:
    """
    Docstring для Value

    :var Example: Value("int","500")
    :var line: "/echo\\"/echo\\\\\\"cat\\\\\\""->
    Value("str" "/echo\\"/echo\\\\\\"cat\\\\\\"")
    :vartype line: Literal['/echo "/echo\\"/echo\\\\\\"cat\\\\\\""']
    :var returns: Описание
    """

    def __init__(self, type_, value):
        self.type = type_
        self.value = value

    def __str__(self):
        return str(self.type) + str(self.value)

    def __repr__(self):
        return f"{self.value}"
