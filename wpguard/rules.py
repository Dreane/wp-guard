"""Правила обнаружения. Это признаки вредоносного кода, а не инструкции по взлому."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: str
    advice: str
    scope: str


def _rule(rule_id, title, severity, pattern, advice, scope) -> Rule:
    return Rule(rule_id, title, severity, pattern, advice, scope)


RULES: tuple[Rule, ...] = (
    _rule(
        "php-eval-decode",
        "Запуск расшифрованной строки через eval",
        "high",
        r"(?i)\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode)\s*\(",
        "Так прячут веб-шеллы. Если файл не ваш, уберите его и смените пароли.",
        "php",
    ),
    _rule(
        "php-assert-input",
        "assert от пользовательского ввода",
        "critical",
        r"(?i)\bassert\s*\(\s*(?:stripslashes\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE)",
        "Конструкция выполняет код из запроса. Удалите файл.",
        "php",
    ),
    _rule(
        "php-preg-e",
        "Устаревший модификатор preg_replace /e",
        "critical",
        r"(?is)\bpreg_replace\s*\(\s*['\"][^'\"]{0,160}/e['\"]",
        "Модификатор /e выполняет подставленный код. В современных плагинах его не бывает.",
        "php",
    ),
    _rule(
        "php-variable-call",
        "Вызов функции, имя которой пришло из запроса",
        "critical",
        r"(?i)\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,80}\]\s*\(",
        "Так устроены однострочные шеллы. Удалите файл, если это не специально написанный вами код.",
        "php",
    ),
    _rule(
        "php-array-map-assert",
        "assert или exec переданы в array_map",
        "critical",
        r"(?i)\b(?:array_map|array_filter|usort)\s*\(\s*['\"](?:assert|eval|system|exec|shell_exec|passthru)['\"]",
        "Косвенный запуск команд. Удалите файл.",
        "php",
    ),
    _rule(
        "php-call-user-exec",
        "call_user_func вызывает команду или eval",
        "critical",
        r"(?i)\bcall_user_func(?:_array)?\s*\(\s*['\"](?:assert|eval|system|exec|shell_exec|passthru|proc_open)['\"]",
        "Косвенный запуск команд. Удалите файл.",
        "php",
    ),
    _rule(
        "php-file-put-input",
        "Запись файла из данных запроса",
        "critical",
        r"(?i)\bfile_put_contents\s*\([^;]{0,200}\$_(POST|REQUEST|GET|COOKIE)",
        "Так шелл сохраняет следующий файл. Удалите этот файл и проверьте каталог ещё раз.",
        "php",
    ),
    _rule(
        "php-shell-input",
        "Системная команда из данных запроса",
        "critical",
        r"(?i)\b(?:shell_exec|passthru|proc_open|popen|system|exec)\s*\([^;]{0,120}\$_(POST|REQUEST|GET|COOKIE)",
        "Код выполняет команды сервера по запросу злоумышленника.",
        "php",
    ),
    _rule(
        "php-create-function",
        "Устаревший create_function",
        "medium",
        r"(?i)\bcreate_function\s*\(",
        "Функция давно удалена из PHP и часто встречается в старых шеллах. Проверьте файл вручную.",
        "php",
    ),
    _rule(
        "php-long-decode-call",
        "Декодирование длинной закодированной строки",
        "high",
        r"(?i)(?:base64_decode|gzinflate|rawurldecode)\s*\(\s*['\"][A-Za-z0-9+/]{180,}={0,2}['\"]",
        "Длинная закодированная строка почти всегда является спрятанным кодом.",
        "php",
    ),
    _rule(
        "php-chr-chain",
        "Строка собрана из цепочки chr()",
        "high",
        r"(?i)(?:chr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){5,}",
        "Так обходят поиск по тексту шелла. Проверьте файл.",
        "php",
    ),
    _rule(
        "php-strrev-eval",
        "eval или assert от перевёрнутой строки",
        "critical",
        r"(?i)(?:eval|assert)\s*\(\s*strrev\s*\(",
        "Маскировка шелла. Удалите файл.",
        "php",
    ),
    _rule(
        "php-pack-eval",
        "eval или assert от pack()",
        "high",
        r"(?i)(?:eval|assert)\s*\(\s*pack\s*\(",
        "Упакованный код. Проверьте файл и удалите его, если это не ваш лицензионный загрузчик.",
        "php",
    ),
    _rule(
        "php-shell-filesman",
        "Признак веб-шелла FilesMan",
        "critical",
        r"FilesMan",
        "Известное семейство веб-шеллов. Удалите файл.",
        "php",
    ),
    _rule(
        "php-shell-c99",
        "Признак веб-шелла c99",
        "critical",
        r"(?i)c99shell",
        "Известное семейство веб-шеллов. Удалите файл.",
        "php",
    ),
    _rule(
        "php-shell-wso",
        "Признак веб-шелла WSO",
        "critical",
        r"(?i)\bWSO\s*[0-9]",
        "Известное семейство веб-шеллов. Удалите файл.",
        "php",
    ),
    _rule(
        "php-shell-b374k",
        "Признак веб-шелла b374k",
        "critical",
        r"(?i)\bb374k\b",
        "Известное семейство веб-шеллов. Удалите файл.",
        "php",
    ),
    _rule(
        "php-shell-r57",
        "Признак веб-шелла r57",
        "critical",
        r"(?i)r57shell",
        "Известное семейство веб-шеллов. Удалите файл.",
        "php",
    ),
    _rule(
        "php-dolly-marker",
        "Признак кампании DollyWay",
        "critical",
        r"(?i)dolly_last_cron|dolly_name|DOLLY_WAY",
        "Кампания скрытых редиректов. Ищите такие же следы в базе и в остальных плагинах: она заражает несколько мест сразу.",
        "php",
    ),
    _rule(
        "php-reversed-marker",
        "Перевёрнутое имя функции декодирования",
        "high",
        r"edoced_46esab|etalfni_zg",
        "Имена base64_decode и gzinflate записаны задом наперёд, чтобы спрятать вызов.",
        "php",
    ),
    _rule(
        "config-auto-prepend",
        "Автоподключение PHP через auto_prepend_file",
        "critical",
        r"(?i)\bauto_(?:prepend|append)_file\b",
        "Сервер будет выполнять указанный файл при каждом запросе. Уберите директиву и проверьте файл, на который она ссылается.",
        "config",
    ),
    _rule(
        "config-external-rewrite",
        "Внешний редирект в .htaccess",
        "high",
        r"(?i)\bRewriteRule\s+\S+\s+https?://",
        "Правило уводит посетителей на чужой адрес. Сверьте файл с чистым .htaccess WordPress.",
        "config",
    ),
    _rule(
        "config-php-in-uploads",
        "В каталоге загрузок разрешён запуск PHP",
        "critical",
        r"(?i)\b(?:SetHandler|AddHandler|AddType)\b[^\n]{0,80}php",
        "Загрузки должны отдаваться как файлы, а не исполняться. Удалите эти директивы.",
        "uploads-config",
    ),
    _rule(
        "js-eval-atob",
        "JavaScript запускает раскодированную строку",
        "high",
        r"(?i)\beval\s*\(\s*(?:window\.)?atob\s*\(",
        "Типичная маскировка вредоносного скрипта. Проверьте, ваш ли это код.",
        "js-suspicious",
    ),
    _rule(
        "js-document-write-unescape",
        "document.write(unescape(...))",
        "high",
        r"(?i)document\.write\s*\(\s*unescape\s*\(",
        "Старый приём подстановки спрятанного скрипта.",
        "js-suspicious",
    ),
    _rule(
        "js-fromcharcode",
        "Длинная цепочка fromCharCode",
        "medium",
        r"(?:fromCharCode\s*\(\s*\d{1,3}\s*\)\s*[+,]?\s*){12,}",
        "Скрипт собран по кодам символов. Проверьте источник.",
        "js-suspicious",
    ),
    _rule(
        "js-coinhive",
        "Признак скрытого майнера",
        "high",
        r"(?i)coinhive|coin-hive|cryptonight",
        "В страницу встроен майнер. Удалите скрипт.",
        "js",
    ),
    _rule(
        "hidden-iframe",
        "Скрытый iframe",
        "medium",
        r"(?i)<iframe\b[^>]{0,300}(?:width\s*=\s*['\"]?[01]\b|height\s*=\s*['\"]?[01]\b|display\s*:\s*none)",
        "Невидимый фрейм часто подгружает редирект или спам. Проверьте адрес внутри него.",
        "html-content",
    ),
)

COMPILED: tuple[tuple[Rule, re.Pattern[str]], ...] = tuple(
    (rule, re.compile(rule.pattern)) for rule in RULES
)
