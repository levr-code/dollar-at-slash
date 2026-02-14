"""main file for das server code"""
import eventlet
eventlet.monkey_patch()
from decimal import Decimal
import sys
import os
import copy
import secrets
import time
import re
import json
import math
import threading
import random
import flask
from flask import Flask, render_template, session, redirect, request
from flask_socketio import SocketIO
from das_helpers import hash_password, Sandbox, Value, eval_expr, Exit, split_by_not_in_blocks
from das_helpers import verify_password, LRUDict, split_block, split_iter
thread_context = threading.local()
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
sandboxes = {}
global_vars = {}
MAX_BUF = 40
cached_blocks = LRUDict()
u2p = {
    "admin": (
        "1e8964cb5dd0620afb74afc55d9a6734:"
        "5988a0508afa4fe785e4bbb648e9cf6a3a43a60b6b9a1c0e60dfbdf5c04e9f47"
    ),
    "rootadmin": (
        "bff22bbf1a660baa3034aed52caa0dbe:"
        "a68dbf55d633c387ad4d131cd568a4cf1a0ec23c57096a10c0a843628c76eeed"
    ),
    "ROOTadmin": (
        "185193589c6c1a7d887f76486d1e5b9f:"
        "1853afe80079638ed3b9a5f912fa5b8df1c7eb99a2c5cfe8a6cca4a7687edbf4"
    ),
}
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
socketio = SocketIO(app, manage_session=True)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"

############################################################
#                        INTERPRETER                       #
############################################################


def sid():
    """Возвращает ID пользователя, работая и в Flask, и в фоновых потоках"""
    # Сначала проверяем, задан ли пользователь специально для этого потока
    if hasattr(thread_context, "user_id"):
        return thread_context.user_id
    # Если нет, берем из сессии Flask (если мы в главном потоке запроса)
    try:
        return session.get("user", "system_user")
    except RuntimeError:
        return "system_user"


def convert_to_type(text):
    """
    Docstring для convert_to_type

    :param text: text you want to convert
    :return: converted to python type value
    :rtype: Value
    """
    if not text:
        return Value("str", "")

    # Clean the input: Remove outer quotes and handle escaped inner quotes
    # This prevents the "o""s"" issue in your error log

    # 1. THE POINTER PROTECTOR
    if "@" in text and (text.startswith("@") or text[3] == "@"):
        at_pos = text.find("@")
        cmd_string = text[at_pos + 1:]
        # 1. Сохраняем оригинал и создаем клон
        original_sandbox = sandboxes[sid()]
        temp_sandbox = copy.deepcopy(original_sandbox)
        # 2. ПОДМЕНЯЕМ активную песочницу на клон ПЕРЕД запуском
        sandboxes[sid()] = temp_sandbox
        try:
            Block(tokenize(cmd_string)).run()
            # Забираем результат из клона
            result = sandboxes[sid()].ib[-1]
            # 3. Возвращаем оригинал на место
            sandboxes[sid()] = original_sandbox
            return convert_to_type(result)
        except Exception as e:
            # В случае ошибки тоже возвращаем оригинал
            sandboxes[sid()] = original_sandbox
            return Value("str", f"ERR: Pointer Failed - {str(e)}")
    # 2. Evaluater
    if "=" in text and (text.startswith("=") or text[3] == "="):
        at_pos = text.find("=")
        cmd_string = text[at_pos + 1:]
        _type = (text[:3]
                 if len(text) >= 3 and text[:3]
                 in ("int", "jsn", "flt", "bit", "nth","dec") else "str")
        try:
            return convert_to_type(_type+str(eval_expr(cmd_string)))
        except Exception as e:
            return Value("str", f"ERR: Evaluter Failed - {str(e)}")
    # 3. THE TYPE PARSER
    # Check prefixes only if the string is long enough
    prefix = text[:3]
    val = text[3:]
    if prefix == "int":
        try:
            return Value("int", int(val))
        except ValueError:
            return Value("int", 0)
    elif prefix == "jsn":
        return Value("jsn", json.loads(val))
    elif prefix == "flt":  # Убираем возможность 何 через flt
        try:
            return Value("flt", float(val))
        except ValueError:
            return Value("flt", 0.0)
    elif prefix == "dec":  # Убираем возможность 何 через flt
        try:
            return Value("dec", Decimal(val))
        except ValueError:
            return Value("dec", Decimal("0"))
    elif prefix == "str":
        return Value("str", val)
    elif prefix == "bit":
        return Value("bit", val.lower() in ("1", "true", "yes", "ok", "well"))
    elif prefix == "nth":
        if val.lower() in ("none", "null", "nothing"):
            return Value("nth", None)
        if val.lower() == "inf":
            return Value("nth", float("inf"))
        if val.lower() == "-inf":
            return Value("nth", float("-inf"))
        return Value("nth", float("nan"))
    # If no prefix matches, it's just a raw string
    return Value("str", prefix + val)


def ttype(text):
    """
    Docstring для ttype

    :param text: text to convert from das type using type
    """
    t = type(text)
    if isinstance(text, Value):
        return text.type + str(text.value)
    try:
        vt = text[:3] not in ["str", "int", "flt", "jsn", "dec", "bit"]
    except (IndexError, TypeError):
        vt = False
    if vt:
        return text
    elif t is int:
        return "int" + str(text)
    elif t is float:
        return "flt" + str(text)
    elif t is bool:
        return "bit" + ("1" if text else "0")
    elif t is Decimal:
        return "dec"+ str(text)
    elif t is list or t is dict:
        return "jsn" + json.dumps(text)
    elif text is None:
        return "nthNone"
    elif isinstance(text, float) and (math.isinf(text) or math.isnan(text)):
        return f"nth{text}"
    else:
        return "str" + str(text)


def tokenize(code):
    """
    Docstring для tokenize

    :param code: code to tokenize

    """
    tokens: list = []
    lines = [split_block(i) for i in split_by_not_in_blocks(code,"\n")]
    raws = [i for i in split_by_not_in_blocks(code,"\n")]
    for i, line in enumerate(lines):
        args = []
        ntargs = []
        a = False
        for j in list(split_iter(line[0]))[1:]:
            a = not a
            if a:
                args.append(j)
                ntargs.append(" ")
            else:
                ntargs.append(j.strip())
        tokens.append(
            Code(
                line[0].split('"')[0],
                args,
                ntargs,
                position=i,
                raw=raws[i],
                blcks=line[1:],
            )
        )
    return tokens


def func_run(code, error=False, line=0):
    sb = sandboxes[sid()]
    sb.push_frame()
    try:
        Code.fileopen(code, error=error, line=line).run()
    finally:
        sb.pop_frame()


class Code:
    """
    Docstring для Code
    executor
    """

    def __repr__(self):
        return (f"Code('{self.value}',{self.args},"
                f"{self.ntargs},position={self.pos})")

    def __str__(self):
        return f"{self.value}+{self.args}"

    def __init__(self, value,
                 args, ntargs,
                 /, blcks=None,
                 position=-1, raw=""):
        if blcks is None:
            blcks = []
        self.value = value.strip()
        self.args = args
        self.pos = position
        self.ntargs = ntargs
        self.blck = blcks
        self.raw = raw

    @staticmethod
    def replace_placeholders(text: str):
        """
        Docstring для replace_placeholders

        :param text: txt where to replace place holders
        :type text: str
        :return:text with replaced placeholders
        """
        ub = sandboxes[sid()].ub
        ib = sandboxes[sid()].ib
        files_map = sandboxes[sid()].files

        def angle_repl(match):
            source = match.group(1)
            index = int(match.group(2))
            if source == "chat":
                return ib[index][3:]
            if source == "litchat":
                return ib[index]
            if source == "userbuf":
                return ub[index] if -len(ub) <= index < len(ub) else ""
            return ""

        def var_repl(match):
            name = match.group(1)
            return (files_map.get(name, "")[4:]
                    if name in files_map else match.group(0))

        text = re.sub(r"<(chat|userbuf|litchat)\s+(-?\d+)>", angle_repl, text)
        text = re.sub(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}", var_repl, text)
        sandboxes[sid()].ub = ub
        sandboxes[sid()].ib = ib
        return text

    @staticmethod
    def fileopen(code, /, line=0, error=False):
        """
        Opens and parses a DAS code block with caching.
        Safe against None cache entries and malformed tokens.
        """

        # ---------- 1. Try cache ----------
        cached = cached_blocks.get(code)
        if cached is not None:
            new_c = copy.deepcopy(cached)
            new_c.error = error
            return new_c

        # ---------- 2. Parse fresh ----------
        tokens: list[Code] = []

        for part in split_by_not_in_blocks(code,"\n"):
            args = []
            ntargs = []
            a = False

            for j in list(split_iter(part))[1:]:
                a = not a
                if a:
                    args.append(j)
                    ntargs.append("{}")
                else:
                    ntargs.append(j.strip())

            pieces = split_block(part)

            tokens.append(
                Code(
                    pieces[0].split('"', maxsplit=1)[0],
                    args,
                    ntargs,
                    position=line,
                    blcks=pieces[1:],
                    raw=part,
                )
            )

        # ---------- 3. Store in cache ----------
        block = Block(tokens)
        cached_blocks[code] = block

        # return clone so cache stays immutable
        new_block = copy.deepcopy(block)
        new_block.error = error
        return new_block

    @staticmethod
    def parse(text: str):
        """replaces ${in} ${username and ${files.all}"""
        ib = sandboxes[sid()].ib
        if "${in}" in text:
            last = ib[-1] if ib else ""
            text = text.replace("${in}", last[3:])
        if "${username}" in text:
            text = text.replace("${username}", sid())
        text = text.replace(
            "${file.all}", str(sandboxes[sid()].files).replace("'", '"')
        )
        sandboxes[sid()].ib = ib
        return text

    @staticmethod
    def __addtochat(val: str):
        ib = sandboxes[sid()].ib
        ub = sandboxes[sid()].ub
        while len(ub) > MAX_BUF:
            ub.pop(0)
        while len(ib) > MAX_BUF:
            ib.pop(0)
        ib.append(ttype(val))
        sandboxes[sid()].ib = ib
        sandboxes[sid()].ub = ub

    @staticmethod
    def say(val: str):
        """
        Docstring для say

        :param val: adds val to ub
        :type val: str
        """
        ib = sandboxes[sid()].ib
        ub = sandboxes[sid()].ub
        ib.append(ttype(val))
        for i in str(val).split("\n"):
            ub.append(i)
            sandboxes[sid()].hist.append(i)
            emit("server_response", i)
        while len(ib) > MAX_BUF:
            ib.pop(0)
        while len(ub) > MAX_BUF:
            ub.pop(0)
        while len(sandboxes[sid()].hist) > MAX_BUF:
            sandboxes[sid()].hist.pop(0)
        sandboxes[sid()].ib = ib
        sandboxes[sid()].ub = ub

    @staticmethod
    def __ibc():
        sandboxes[sid()].ib.clear()

    @staticmethod
    def __ubc():
        emit("clear_ub", "")
        sandboxes[sid()].ub.clear()

    def run(self):
        """the executing methode of Code class"""
        try:
            ib = sandboxes[sid()].ib
            files: dict[str] = dict(sandboxes[sid()].files)
            if len(self.value) == 0:
                return
            la = len(self.args)
            args = self.args
            self.args = [
                convert_to_type(
                    self.parse(self.replace_placeholders(self.parse(v)))
                ).value
                if not v.startswith(("/for", "/file.save"))
                else v
                for v in self.args
            ]
            if self.value == "/help" and la == 0:
                Block(tokenize("""/echo "@#\\"sys/bin/help\\"" """)).run()
            elif self.value == "/docs":
                if la == 0:
                    # Показываем список всех файлов в папке docs
                    self.say(
                        "Доступные инструкции: "
                        + ", ".join(
                            [
                                k.replace("sys/bin/docs/", "")
                                for k in sandboxes[sid()].dict(files).keys()
                                if k.startswith("sys/bin/docs/")
                            ]
                        )
                    )
                else:
                    # Запускаем файл конкретной инструкции
                    # Используем кавычки внутри tokenize,
                    # чтобы путь считался одним аргументом
                    Block(
                        tokenize(f'/echo "@#\\"sys/bin/docs/{self.args[0]}\\""')
                    ).run()
                return
            elif self.value == "/math.add" and la == 2:
                self.__addtochat(self.args[0] + self.args[1])
            elif self.value == "/pass":
                pass
            elif self.value == "/math.sub" and la == 2:
                self.__addtochat(self.args[0] - self.args[1])
            elif self.value == "/chat.item" and la == 1:
                self.say(sandboxes[sid()].ib[self.args[0]])
            elif self.value == "/math.mul" and la == 2:
                self.__addtochat(self.args[0] * self.args[1])
            elif self.value == "/math.div" and la == 2:
                self.__addtochat(
                    self.args[0] / self.args[1]
                    if self.args[1] != 0
                    else float("inf")
                )
            elif self.value == "/math.pow" and la == 2:
                self.__addtochat(self.args[0] ** self.args[1])
            elif self.value == "/math.cos" and la == 1:
                self.__addtochat(math.cos(self.args[0]))
            elif self.value == "/math.cosh" and la == 1:
                self.__addtochat(math.cosh(self.args[0]))
            elif self.value == "/math.sin" and la == 1:
                self.__addtochat(math.sin(self.args[0]))
            elif self.value == "/math.sinh" and la == 1:
                self.__addtochat(math.sinh(self.args[0]))
            elif self.value == "/lambda" and la == 1:
                files[self.args[0]] = self.blck[0]
            elif self.value == "/math.tan" and la == 1:
                self.__addtochat(math.tan(self.args[0]))
            elif self.value == "/math.tanh" and la == 1:
                self.__addtochat(math.tanh(self.args[0]))
            elif self.value == "/math.comb" and la == 1:
                self.__addtochat(math.comb(self.args[0]))
            elif self.value == "/whilel":
                while True:
                    cond = convert_to_type(
                        self.replace_placeholders(args[0])
                    ).value

                    if not cond:
                        break

                    self.fileopen(self.replace_placeholders(self.blck[0]), error=True).run()
                    time.sleep(0.01)  # so server won't be frozen
            elif self.value == "/while":
                while True:
                    cond = convert_to_type(
                        self.replace_placeholders(args[0])
                    ).value

                    if not cond:
                        break

                    self.fileopen(self.replace_placeholders(self.args[1]), error=True).run()
                    time.sleep(0.01)  # so server won't be frozen
            elif self.value == "/tly":
                for candidate in self.blck:
                    try:
                        self.fileopen(self.replace_placeholders(candidate), error=True).run()
                        break  # stop after first success
                    except Exception as e:
                        print(f"/tly excepted {repr(e)}")
                        continue
            elif self.value == "/try":
                # /try "code"
                if la == 1:
                    try:
                        self.fileopen(self.replace_placeholders(self.args[0]), error=True).run()
                    except Exception as e:
                        print(f"/try excepted {repr("e")}")

                # /try "code" :fails: "fallback"
                elif la == 2 and self.ntargs[1] == ":fails:":
                    try:
                        self.fileopen(self.replace_placeholders(self.args[0]), error=True).run()
                    except Exception as e:
                        print(f"/try excepted {repr("e")}")
                        self.fileopen(self.replace_placeholders(self.args[1]), error=True).run()
            elif self.value == "/math.sum" and la == 2:
                self.__addtochat(sum(i for i in self.args))
            elif self.value == "/len" and la == 1:
                self.__addtochat(len(self.args[0]))
            elif self.value == "/sys.theme" and la == 1:
                emit("settheme", self.args[0])
                sandboxes[sid()].theme = self.args[0]
            elif self.value == "mem.malloc":  # for no confusion returns a "memointer"
                self.__addtochat(sandboxes[sid()].malloc(self.args[0]))
            elif self.value == "mem.free":  # frees a memointer
                addr = self.args[0]
                sandboxes[sid()].free(addr)
            elif self.value == "mem.read":  # reads from memointer
                val = sandboxes[sid()].heap_read(self.args[0], self.args[1])
                self.__addtochat(val)
            elif self.value == "mem.write":
                sandboxes[sid()].heap_write(self.args[0], self.args[1], self.args[2])
            elif self.value == "/global.set" and la == 2:
                global_vars.setdefault(self.args[0])
                global_vars[self.args[0]] = self.args[1]
            elif self.value == "/global.get" and la == 1:
                self.__addtochat(global_vars[self.args[0]])
            elif self.value == "/hello" and la == 1:
                self.__addtochat(f"Hello {self.args[0]}!")
            elif self.value == "/ask" and la == 1:
                self.__addtochat(f"{self.args[0]}?")
            elif self.value == "/echo" and la == 1:
                self.say(self.args[0])
            elif self.value == "/sys.addchat" and la == 1:
                self.__addtochat(self.args[0])
            elif self.value == "/file.save" and la == 2:
                files.setdefault(self.args[0])
                if isinstance(self.args[1], str):
                    files[self.args[0]] = (
                        self.args[1].replace("'", '"').replace("`", "'")
                    )
                else:
                    files[self.args[0]] = (
                        ttype(self.args[1]).replace("'", '"').replace("`", "'")
                    )
            elif (self.value.startswith("$")
                  and self.value[-1] == "=" and la == 1):
                block = self.fileopen(self.args[0], line=self.pos)
                block.run()
                var_name = self.value[1:-1]
                files[var_name] = sandboxes[sid()].ib[-1]
            elif (self.value.startswith("$")
                  and self.value[-1] == "$" and la == 1):
                var_name = self.value[1:-1]
                files[var_name] = ttype(self.args[0])
            elif self.value == "/file.delete" and la == 1:
                files.pop(self.args[0])
                files.setdefault("MyaOS", "txt/not existing... yet")
            elif self.value == "/file.deleteall" and la == 0:
                files.clear()
            elif self.value == "/file.ext" and la == 1:
                self.__addtochat(files[self.args[0]][:3])
            elif self.value == "/sys.wait" and la == 1:
                time.sleep(self.args[0])
            elif self.value == "/file.movedir" and la == 2:
                src_dir, dest_dir = self.args[0], self.args[1]
                # Гарантируем слэши для безопасности
                if not src_dir.endswith("/"):
                    src_dir += "/"
                if not dest_dir.endswith("/"):
                    dest_dir += "/"
                # Собираем список файлов, которые нужно перенести
                to_move = [f for f in files if f.startswith(src_dir)]
                for old_path in to_move:
                    # Отрезаем старый префикс и клеим новый
                    new_path = dest_dir + old_path[len(src_dir):]
                    if new_path not in files:
                        files[new_path] = files.pop(old_path)
                        # Не забываем про твои типы данных!
            elif self.value == "/for" and la == 3 and self.ntargs[1] == "in":
                count = self.args[1]
                var = self.args[0]
                body = args[2].replace("'", '"')
                files.setdefault(var, "var/0")
                for i in range(count) if isinstance(count, int) else count:
                    files[var] = f"var/{i}"
                    bb = self.fileopen(
                        self.replace_placeholders(
                            body.replace("${" + var + "}", str(i))
                        ),
                        line=self.pos,
                    )
                    bb.run()
                files.pop(var)
            elif self.value == "/fol" and la == 2 and self.ntargs[1] == "in":
                count = self.args[1]
                var = self.args[0]
                body = self.blck[0]
                files.setdefault(var, "var/0")
                for i in range(count) if isinstance(count, int) else count:
                    files[var] = f"var/{i}"
                    bb = self.fileopen(
                        self.replace_placeholders(
                            body.replace("${" + var + "}", str(i))
                        ),
                        line=self.pos,
                    )
                    bb.run()
                files.pop(var)
            elif self.value == "/ifl" and len(self.args) == 1:
                if self.args[0]:
                    self.fileopen(self.blck[0]).run()
                elif len(self.blck) == 2:
                    self.fileopen(self.blck[1]).run()
            elif self.value == "/if" and len(self.args) >= 2:
                condition = False
                code_idx = -1
                else_idx = -1
                for idx, nt in enumerate(self.ntargs):
                    if nt == "/else":
                        else_idx = idx
                        break
                if else_idx == 2 or (else_idx == -1
                                     and len(self.args) in (2, 3)):
                    condition = self.args[0] is True or self.args[0] == 1
                    code_idx = 1
                elif else_idx == 4 or (else_idx == -1 and len(self.args) >= 4):
                    a, op, b = self.args[0], self.args[1], self.args[2]
                    if op == "=":
                        condition = a == b
                    elif op == "!=":
                        condition = a != b
                    elif op == ">":
                        condition = a > b
                    elif op == "<":
                        condition = a < b
                    elif op == ">=":
                        condition = a >= b
                    elif op == "<=":
                        condition = a <= b
                    code_idx = 3
                if condition and code_idx != -1:
                    self.fileopen(self.args[code_idx].replace("'", '"')).run()
                elif not condition and else_idx != -1:
                    self.fileopen(self.args[else_idx].replace("'", '"')).run()
            elif self.value == "/file.ls" and la == 1:
                target = self.args[0]
                if not target.endswith("/"):
                    target += "/"  # Гарантируем слэш в конце
                # Твоя магия генерации "папок" на лету
                nodes = nodes = {
                    parts[0] if len(parts) == 1 else parts[0] + "/"
                    for f in files
                    if (f.startswith(target)
                        and (parts := f[len(target):].split("/")))
                }
                if nodes:
                    self.__addtochat(" | ".join(sorted(nodes)))
                else:
                    self.say("")
            elif self.value in {"/file.open", "#"} and len(self.args) >= 1:
                if self.args[0] not in files:
                    Block(tokenize(f'/file.ls "{self.args[0]}"')).run()
                    return
                file = files[self.args[0]][4:]
                rgs = [convert_to_type(i).value for i in args]
                if not files[rgs[0]].startswith(
                    ("com/", "fnc/", "lst/", "var/", "txt/", "lfn")
                ):
                    self.__addtochat(files[self.args[0]])
                    return
                if files[rgs[0]][:4] == "com/":
                    block = self.fileopen(file, line=self.pos)
                    block.run()
                elif files[rgs[0]][:4] == "lst/":
                    for i in split_by_not_in_blocks(files[rgs[0]][4:]):
                        self.__addtochat(i)
                elif files[self.args[0]][:4] == "fnc/":
                    for i in range(len(rgs[1:])):
                        file = file.replace("${" + str(i) + "}",
                                            str(rgs[1:][i]))
                    block = self.fileopen(file, line=self.pos)
                    block.run()
                elif files[self.args[0]][:4] == "lfn/":
                    for i in range(len(rgs[1:])):
                        file = file.replace("${" + str(i) + "}",
                                            str(rgs[1:][i]))
                    func_run(file, line=self.pos)
                elif (
                    files[self.args[0]][:4] == "txt/"
                    or files[self.args[0]][:4] == "var/"
                ):
                    self.__addtochat(f"{file}")
                else:
                    self.__addtochat(files[self.args[0]])
            elif self.value == "/ub.clear" and len(self.args) == 0:
                self.__ubc()
            elif self.value == "/file.deleteall" and len(self.args) == 0:
                files.clear()
                files.setdefault("MyaOS", "txt/not existing... yet")
            elif self.value == "/ib.clear" and len(self.args) == 0:
                self.__ibc()
            elif self.value == "/str.upper" and len(self.args) == 1:
                self.__addtochat(self.args[0].upper())
            elif self.value == "/str.lower" and len(self.args) == 1:
                self.__addtochat(self.args[0].lower())
            elif self.value == "/str.replace" and la == 3:
                self.__addtochat(self.args[0].replace(self.args[1],
                                                      self.args[2]))
            elif self.value == "/canvas.line":
                emit(
                    "drawline",
                    {
                        "fromx": self.args[0][0],
                        "fromy": self.args[0][1],
                        "tox": self.args[1][0],
                        "toy": self.args[1][1],
                        "color": self.args[2],
                    },
                )
            elif self.value == "/canvas.text":
                emit(
                    "drawtext",
                    {
                        "x": self.args[0][0],
                        "y": self.args[0][1],
                        "text": self.args[1],
                        "font": self.args[2],
                        "color": self.args[3],
                    },
                )
            elif self.value == "/canvas.rect":
                emit(
                    "drawrect",
                    {
                        "a1": self.args[0][0],
                        "a2": self.args[0][1],
                        "a3": self.args[0][2],
                        "a4": self.args[0][3],
                        "color": self.args[1],
                    },
                )
            elif self.value == "/canvas.clear":
                emit("canvasclear")
            elif self.value == "/math.gt" and la == 2:  # Greater Than
                self.__addtochat(
                    self.args[0] > self.args[1]
                )  # ttype сам сделает из этого bit1/0
            elif self.value == "/math.lt" and la == 2:  # Less Than
                self.__addtochat(
                    self.args[0] < self.args[1]
                )  # ttype сам сделает из этого bit1/0
            elif self.value == "/math.eq" and la == 2:  # Equal
                self.__addtochat(self.args[0] == self.args[1])
            elif self.value == "/bit.or" and la == 2:  # OR
                self.__addtochat(self.args[0] or self.args[1])
            elif self.value == "/bit.and" and la == 2:  # And
                self.__addtochat(self.args[0] and self.args[1])
            elif self.value == "/bit.xor" and la == 2:  # And
                self.__addtochat(self.args[0] ^ self.args[1])
            elif self.value == "/bit.not" and la == 1:  # Not
                self.__addtochat(not self.args[0])
            elif self.value == "o":
                op = self.ntargs[1]
                if la == 1:
                    if op == "!":
                        self.__addtochat(not self.args[0])
                    elif op == "%?":
                        self.__addtochat(random.random() <= self.args[0])
                    elif op == "%":
                        self.__addtochat(self.args[0] / 100)
                    elif op == "++":
                        files[self.args[0]] = files[self.args[0]][:4] + ttype(
                            convert_to_type(files[self.args[0]][4:]).value + 1
                        )
                        self.__addtochat(files[self.args[0]])
                    elif op == "file exists":
                        self.__addtochat(self.args[0] in files)
                    elif op == "abs":
                        self.__addtochat(abs(self.args[0]))
                    elif op == "--":  # Декремент
                        files[self.args[0]] = files[self.args[0]][:4] + ttype(
                            convert_to_type(files[self.args[0]][4:]).value - 1
                        )
                        self.__addtochat(files[self.args[0]])
                    elif op == "@":
                        self.__addtochat(len(bytearray(str(self.args[0]),
                                                       "utf-8")))
                    return
                if la == 2:
                    a, b = self.args[0], self.args[1]
                    if op == ">":
                        self.__addtochat(a > b)
                    elif op == "<":
                        self.__addtochat(a < b)
                    elif op == "===":
                        self.__addtochat(ttype(a) == ttype(b))
                    elif op == "==":
                        self.__addtochat(a == b)
                    elif op == "||":
                        self.__addtochat(a or b)
                    elif op == "&&":
                        self.__addtochat(a and b)
                    elif op == "in":
                        self.__addtochat(a in b)
                    elif op == "+":
                        if isinstance(a, dict) and isinstance(b, dict):
                            self.__addtochat({**a, **b})
                        else:
                            self.__addtochat(a + b)
                    elif op == "-":
                        if isinstance(a, list) and isinstance(b, list):
                            self.__addtochat([item
                                              for item in a
                                              if item not in b])
                        elif isinstance(a, str) and isinstance(b, str):
                            self.__addtochat(a.replace(b, ""))
                        else:
                            self.__addtochat(a - b)
                    elif op == "*":
                        self.__addtochat(a * b)
                    elif op == "/":  # Деление
                        self.__addtochat(a / b if b != 0 else float("inf"))
                    elif op == "%":
                        self.__addtochat(a % b)
                    elif op == "//":
                        self.__addtochat(a // b)
                    elif op == "**":
                        self.__addtochat(a**b)
                    elif op == "^":
                        self.__addtochat(a ^ b)
                    elif op == "&":  # Побитовое И
                        self.__addtochat(a & b)
                    elif op == "|":  # Побитовое ИЛИ
                        self.__addtochat(a | b)
                    elif op == "<<":
                        self.__addtochat(a << b)
                    elif op == ">>":
                        self.__addtochat(a >> b)
                    elif op == "$":
                        self.__addtochat(convert_to_type(ttype(b)[:3]
                                                         + str(a)))
                    elif op == "=":
                        files[self.args[0]] = (files[self.args[0]][:4]
                                               + ttype(b))
                        self.__addtochat(b)
                    elif op == "+=":  # Прибавить к переменной
                        new_v = (convert_to_type(files[self.args[0]][4:]).value
                                 + b)
                        files[self.args[0]] = (files[self.args[0]][:4]
                                               + ttype(new_v))
                        self.__addtochat(new_v)
                    elif op == "-=":  # Отнять от переменной
                        new_v = (convert_to_type(files[self.args[0]][4:]).value
                                 - b)
                        files[self.args[0]] = (files[self.args[0]][:4]
                                               + ttype(new_v))
                        self.__addtochat(new_v)
                    elif op == "?:":
                        self.__addtochat(a if a else b)
                    elif op == "..":
                        self.__addtochat(b[0] <= a <= b[1])
                    elif op == "~":
                        self.__addtochat(bool(re.search(str(b), str(a))))
                    elif op == "...":
                        self.__addtochat(list(range(a, b)))
                    elif op == "type is":
                        self.__addtochat(isinstance(a, type(b)))
                    elif op == "starts with":  # StartsWith
                        self.__addtochat(str(a).startswith(str(b)))
                    elif op == "ends with":  # EndsWith
                        self.__addtochat(str(a).endswith(str(b)))
                    return
                if (la == 3
                        and self.ntargs[1] == "?"
                        and self.ntargs[3] == "::"):
                    self.__addtochat(self.args[1]
                                     if self.args[0]
                                     else self.args[2])
                    return
            elif self.value == "/lst.in" and la == 2:
                self.__addtochat(self.args[0] in self.args[1])
            elif self.value == "/str.split" and la == 2:
                self.__addtochat(self.args[0].split(self.args[1]))
            elif self.value == "/lst.join" and la == 2:
                # Соединяем список в строку через разделитель
                # Пример: /lst.join "jsn[\"a\", \"b\"]" ", " -> str"a, b"
                self.__addtochat(str(self.args[1]).join(map(str, self.args[0])))
            # --- LST: Манипуляция данными ---
            elif self.value == "/lst.get" and la == 2:
                # args[0] - сам список/объект, args[1] - индекс или ключ
                try:
                    res = self.args[0][self.args[1]]
                    self.__addtochat(res)
                except (IndexError, KeyError, TypeError) as e:
                    raise Exit(
                        f"Key/Index '{self.args[1]}' not found", "LST_Error"
                    ) from e
            elif self.value == "/lst.set" and la == 3:
                # args[0] - список, args[1] - индекс, args[2] - новое значение
                try:
                    target = self.args[0]
                    target[self.args[1]] = self.args[2]
                    self.__addtochat(target)  # Возвращаем обновленный объект в ib
                except (IndexError, TypeError) as e:
                    raise Exit("Cannot set value to this object", "LST_Error") from e
            elif self.value == "/file.rname" and len(self.args) == 2:
                f = files[self.args[0]]
                del files[self.args[0]]
                files.setdefault(self.args[1], f)
            elif self.value == "/file.move" and la == 2:
                src, dest = self.args[0], self.args[1]
                if src in files:
                    if dest.endswith("/"):
                        # Берем имя файла (то, что после последнего слэша)
                        # Если слэшей нет (файл в корне), берем всё имя
                        filename = src.split("/")[-1]
                        new_path = dest + filename
                    else:
                        # Если dest не папка, работаем как обычный rename
                        new_path = dest
                    if new_path not in files:
                        files[new_path] = files.pop(src)
                    else:
                        self.say("Error: Destination exists!")
            elif self.value == "/file.text" and len(self.args) == 1:
                self.__addtochat(files[self.args[0]])
            elif self.value == "/file.copy" and len(self.args) == 2:
                f = files[self.args[0]]
                files.setdefault(self.args[1], f)
            elif self.value == "/file.add" and len(self.args) == 2:
                f = files[self.args[0]]
                files[self.args[0]] = files[self.args[0]] + self.args[1]
            elif self.value == "/sys.raise" and len(self.args) == 2:
                raise Exit(self.args[1], name=self.args[0])
            elif self.value == "/sys.saveall" and la == 0:
                command = "jsn" + json.dumps(
                    {"files": files, "ib": ib, "ub": sandboxes[sid()].ub}
                )
                command = command.replace("\\", "\\\\")
                command = command.replace('"', '\\"')
                self.say(command)
            elif self.value == "/sys.restore" and la == 1:
                # args[0] уже будет словарем (dict), так как convert_to_type его распарсил
                data = self.args[0]
                if isinstance(data, dict):
                    sandboxes[sid()].files = data.get("files", {})
                    sandboxes[sid()].ib = data.get("ib", [])
                    # Очищаем и заполняем ub
                    self.__ubc()
                    for line in data.get("ub", []):
                        self.say(line)
            else:
                raise Exit(str(self), "UnknownCommand")
            self.args = args
            sandboxes[sid()].ib = ib
            sandboxes[sid()].files = files
        except Exception:
            self.__addtochat(float("nan"))
            raise


class Block:
    """
    Docstring для Block
    a group of Code classes
    """

    def __init__(self, instructions, /, error=False):
        self.instructions = instructions
        self.error = error

    def __repr__(self):
        return f"Block([{','.join([repr(i) for i in self.instructions])}])"

    def __str__(self):
        return f"{','.join([str(i) for i in self.instructions])}"

    def run(self):
        """
        Docstring для run

        runs all Code objects
        """
        if not self.error:
            for instr in self.instructions:
                try:
                    instr.run()
                except Exit as e:
                    if not e.name.endswith("Warning"):
                        Code.say(
                            f"""{e.name}: {e}, at line {instr.pos + 1}
{instr.raw}
{"^" * len(instr.raw)}"""
                        )
                    else:
                        Code.say(f"{e.name}: {e}")
                except BaseException as e:
                    print(f"""{type(e).__name__}: {e}, at line {instr.pos + 1}
{instr.raw}
{"^" * len(instr.raw)}""")
                    Code.say(
                        f"""{type(e).__name__}: {e}, at line {instr.pos + 1}
{instr.raw}
{"^" * len(instr.raw)}"""
                    )
        else:
            for instr in self.instructions:
                instr.run()


############################################################
#                      NOT INTERPRETER                     #
############################################################


def setup_rotes():
    """Setups all needed flask."""

    @app.route("/fav.ico")
    def favicon():
        """returns favicon"""
        return flask.send_from_directory(
            app.static_folder, "fav.ico", mimetype="image/x-icon"
        )

    @app.route("/favicon.ico")
    def fav():
        """returns favicon"""
        return flask.send_from_directory(
            app.static_folder, "fav.ico", mimetype="image/x-icon"
        )

    @app.route("/auth")
    def auth():
        """
        Docstring для auth
        later it redirects to /auth/done where the logic is done and this is just the main auth page
        """
        return render_template("auth.html")

    @app.route("/auth/done", methods=["GET", "POST"])
    def authdone():
        """
        Docstring для authdone
        auth logic
        :return: where to redirect
        :rtype: Response
        """
        if request.method == "POST":
            username = request.form.get("user").strip()
            password = request.form.get("pass")
            if username not in u2p or (
                username in u2p
                and verify_password(password, u2p[username])
                and username
                and password.strip()
            ):
                if username not in u2p:
                    u2p.setdefault(username, hash_password(password))
                    sandboxes.setdefault(username, Sandbox())
                session["user"] = username
                return redirect("/")
            return redirect("/auth")
        return redirect("/auth")

    @app.route("/logout")
    def logout():
        """
        Docstring для logout
        logs out by clearing session
        :return:home redirect to check is session cleared
        """
        session.clear()
        return redirect("/")

    @app.route("/")
    def home():
        """
        home page
        """
        if "user" not in session:
            return redirect("/auth")

        if sid() not in sandboxes:
            sandboxes[sid()] = Sandbox()

        return render_template("tests.html", user=session["user"])

    def send_time():
        """time sender"""
        while True:
            socketio.emit("time_update", time.strftime("%H:%M:%S"))
            time.sleep(1)

    @socketio.on("client_input_response")
    def handle_input_response(data):
        if "user" not in session:
            return False
        var_name = data.get("var")
        text = data.get("text", "")
        # Визуализируем ввод пользователя в консоли
        emit("server_response", text)
        sandboxes[sid()].hist.append(text)

        if var_name:
            # Сохраняем как переменную
            sandboxes[sid()].files[var_name] = "var/" + text
            emit("server_response", f"[System]: Saved to ${var_name}")
        else:
            # Сохраняем в буфер (ib/ub)
            ib = sandboxes[sid()].ib
            ub = sandboxes[sid()].ub
            # Используем ttype, чтобы "123" стало int123, а "true" -> bit1
            ib.append(ttype(text))
            ub.append(text)
            # Контроль размера
            if len(ib) > MAX_BUF:
                ib.pop(0)
            if len(ub) > MAX_BUF:
                ub.pop(0)
            if len(sandboxes[sid()].hist) > MAX_BUF:
                sandboxes[sid()].hist.pop(0)
            sandboxes[sid()].ib = ib
            sandboxes[sid()].ub = ub
        return True

    @socketio.on("connect")
    def on_connect():
        """connect handler"""
        if "user" not in session:
            return False
        if sid() not in sandboxes:
            sandboxes.setdefault(sid(), Sandbox())
        else:
            emit("clear_ub", "")
            for i in sandboxes[sid()].hist:
                emit("server_response", i)
        return True

    @socketio.on("client_message")
    def handle_client_message(data):
        """
        Docstring для handle_client_message

        :param data: clients command
        :return: is it ok?
        :rtype: Literal[False] | None
        """
        if "user" not in session:
            return False
        Code("/ub.clear",[],[],None,raw="/ub.clear").run()
        sandboxes[sid()].hist.clear()
        sandboxes[sid()].ib.clear()
        sandboxes[sid()].files.clear()
        if not isinstance(data["text"], str):
            emit("server_response", "Error: input must be a string")
            sandboxes[sid()].hist.append("Error: input must be a string")
            return False
        Block(tokenize(data["text"])).run()
        return True

    threading.Thread(target=send_time, daemon=True).start()


if __name__ == "__main__":
    # Костыль
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as theFile:
                cd = theFile.read()
            session = {"user": "system_user"}
            sandboxes[session["user"]] = Sandbox()

            def emit(event, data=None):
                """
                Docstring для emit

                emit is a replacement for socketio.emit

                :param event: event to emit
                :param data: text for the event
                """
                if event == "server_response":
                    print(data)
            Block(tokenize(cd)).run()
        else:
            print(f"Ошибка: Файл {file_path} не найден.")
    else:
        print("Аргументы не найдены. Запуск веб-интерфейса...")
        setup_rotes()
        from flask_socketio import emit

        socketio.run(app, host="0.0.0.0", port=80)
