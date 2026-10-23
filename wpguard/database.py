"""Проверка базы WordPress. Запросы только на чтение."""

from __future__ import annotations

import re
from typing import Any

from wpguard.models import Finding, Site

HEX_NAME = re.compile(r"^[0-9a-fA-F]{16,64}$")
HEX_LOGIN = re.compile(r"^[0-9a-fA-F]{8,32}$")
HEX_EMAIL = re.compile(r"^[0-9a-f]{6,}@[0-9a-f]{6,}\.com$", re.IGNORECASE)
PLUGIN_PATH = re.compile(r's:\d+:"([^"\\]+\.php)"')


class DatabaseError(Exception):
    pass


def _hide(text: str, secret: str | None) -> str:
    if secret:
        text = text.replace(secret, "***")
    return text[:300]


def _finding(severity, code, title, location, evidence, advice, **details) -> Finding:
    return Finding(
        severity=severity,
        category="database",
        code=code,
        title=title,
        location=location,
        evidence=evidence[:180],
        advice=advice,
        details=details,
    )


def is_administrator(capabilities: str) -> bool:
    return '"administrator";b:1' in capabilities or '"administrator";b:1;' in capabilities


def classify_user(login: str, email: str, capabilities: str, registered: str) -> list[Finding]:
    admin = is_administrator(capabilities or "")
    found: list[Finding] = []
    hex_login = HEX_LOGIN.fullmatch(login or "") is not None
    hex_email = HEX_EMAIL.fullmatch(email or "") is not None
    if hex_login or hex_email:
        found.append(_finding(
            "critical" if admin else "high",
            "suspicious-account",
            "Учётная запись похожа на спрятанного администратора",
            f"user:{login}",
            f"{email}; зарегистрирован {registered}",
            "Такие имена из шестнадцатеричных символов оставляют кампании вроде DollyWay и прячут их от списка в админке. Удалите пользователя в базе, если вы его не создавали.",
        ))
    elif admin and login.lower() in {"admin", "administrator", "wpadmin", "wp-admin"}:
        found.append(_finding(
            "medium",
            "generic-admin",
            "Администратор со стандартным именем",
            f"user:{login}",
            email,
            "Имя admin перебирают первым. Заведите именную учётку и удалите общую.",
        ))
    return found


def classify_option(name: str, php_at: int, eval_at: int, dolly_at: int, script_at: int, length: int) -> list[Finding]:
    found: list[Finding] = []
    if HEX_NAME.fullmatch(name or ""):
        hot = php_at or eval_at or dolly_at or length > 200
        found.append(_finding(
            "critical" if hot else "high",
            "hex-option",
            "Настройка с именем из одних шестнадцатеричных символов",
            f"option:{name}",
            f"длина значения {length}",
            "Ядро так настройки не называет. У DollyWay в такой строке лежит список узлов редиректа. Удалите запись, если не знаете её назначение.",
        ))
        return found
    if name in {"rewrite_rules", "cron"}:
        return found
    if php_at:
        found.append(_finding(
            "critical", "option-php", "В настройке лежит PHP",
            f"option:{name}", f"позиция {php_at}",
            "В wp_options не должно быть исполняемого PHP. Удалите значение и ищите такой же фрагмент в файлах.",
        ))
    elif dolly_at:
        found.append(_finding(
            "critical", "option-dolly", "В настройке есть признак DollyWay",
            f"option:{name}", f"позиция {dolly_at}",
            "Удалите запись и проверьте остальные опции и плагины: кампания заражает несколько мест.",
        ))
    elif eval_at:
        found.append(_finding(
            "high", "option-eval", "В настройке есть eval(",
            f"option:{name}", f"позиция {eval_at}",
            "Проверьте значение опции. Так сохраняют код, который потом запускает заражённый плагин.",
        ))
    elif script_at and not name.startswith("_transient"):
        found.append(_finding(
            "medium", "option-script", "В настройке есть тег script",
            f"option:{name}", f"позиция {script_at}, длина {length}",
            "Так прячут редирект и спам в виджетах. Оставьте только те скрипты, которые вы вставляли сами.",
        ))
    return found


def classify_post(post_id: int, post_type: str, title: str, php_at: int, eval_at: int, b64_at: int, dolly_at: int, iframe_at: int, script_at: int) -> list[Finding]:
    label = f"{post_type} #{post_id} {title}".strip()
    if php_at or eval_at or b64_at or dolly_at:
        return [_finding(
            "critical", "post-code", "В содержимом записи есть исполняемый или закодированный код",
            label, f"php={php_at} eval={eval_at} base64={b64_at} dolly={dolly_at}",
            "Откройте запись в базе и уберите чужой фрагмент. Затем ищите тот же код в файлах, иначе он вернётся.",
        )]
    if iframe_at:
        return [_finding(
            "high", "post-iframe", "В записи есть iframe",
            label, f"позиция {iframe_at}",
            "Проверьте адрес фрейма. Скрытые фреймы уводят посетителей на чужие сайты.",
        )]
    if script_at:
        return [_finding(
            "medium", "post-script", "В записи есть тег script",
            label, f"позиция {script_at}",
            "Оставьте скрипт, только если это ваш счётчик или вставка. Чужие адреса удалите.",
        )]
    return []


def classify_cron(php_at: int, eval_at: int, dolly_at: int, length: int) -> list[Finding]:
    if not (php_at or eval_at or dolly_at):
        return []
    return [_finding(
        "critical" if (php_at or dolly_at) else "high",
        "cron-payload",
        "В планировщике WordPress есть признак вредоносной задачи",
        "option:cron",
        f"длина {length}; php={php_at} eval={eval_at} dolly={dolly_at}",
        "Откройте опцию cron и удалите незнакомую задачу. DollyWay обновляет список редиректов именно через cron.",
    )]


def plugin_paths(serialized: str) -> list[str]:
    return PLUGIN_PATH.findall(serialized or "")


def _connect(site: Site):
    try:
        import pymysql
    except ImportError as exc:
        raise DatabaseError("Установите пакет pymysql: pip install pymysql") from exc
    config = site.config
    prefix = config.table_prefix
    if not re.fullmatch(r"[A-Za-z0-9_]+", prefix or ""):
        raise DatabaseError("Префикс таблиц содержит недопустимые символы")
    try:
        connection = pymysql.connect(
            host=config.db_host,
            port=config.db_port,
            user=config.db_user,
            password=config.db_password,
            database=config.db_name,
            unix_socket=config.db_socket,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=10,
            read_timeout=90,
            write_timeout=30,
        )
    except Exception as exc:
        raise DatabaseError(_hide(str(exc), config.db_password)) from exc
    return connection, prefix


def _query(connection, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return list(cursor.fetchall())


def _version_findings(client, version_text: str) -> list[Finding]:
    if client is None:
        return []
    from wpguard.vulns import findings_from_vulnerabilities
    match = re.search(r"(\d+\.\d+\.\d+)", version_text)
    if not match:
        return []
    version = match.group(1)
    kind = "mariadb" if "mariadb" in version_text.lower() else "mysql"
    try:
        from wpguard.vulns import vulnerabilities_for
        data, items = vulnerabilities_for(client, kind, version)
    except Exception as exc:
        return [_finding(
            "low", "db-version-unchecked", "Версия СУБД не сверена с базой уязвимостей",
            kind, str(exc)[:180], "Повторите проверку с сетью.",
        )]
    found = []
    if data.get("status") == "d":
        found.append(_finding(
            "medium", "db-eol", "Ветка СУБД снята с поддержки",
            kind, version_text[:120],
            "Обновите MySQL или MariaDB на хостинге.",
        ))
    found.extend(findings_from_vulnerabilities(data, items, version, kind, f"{kind} {version}"))
    for item in found:
        if item.category == "vulnerability":
            item.category = "database"
    return found


def scan(site: Site, client=None) -> list[Finding]:
    config = site.config
    missing_login = not config.db_name or not config.db_user
    missing_password = not config.db_password
    if missing_login or missing_password:
        return [_finding(
            "info", "database-skipped", "База не проверялась",
            "wp-config.php",
            "нет литерала пароля или имени базы",
            "Передайте доступ: --db-name --db-user --db-password или поправьте define() в wp-config.php.",
        )]
    try:
        connection, prefix = _connect(site)
    except DatabaseError as exc:
        return [_finding(
            "high", "database-connect", "Не удалось подключиться к базе",
            config.db_name or "", str(exc),
            "Проверьте хост, пользователя и пароль. Пароль в текст ошибки не попадает.",
        )]
    users = prefix + "users"
    usermeta = prefix + "usermeta"
    options = prefix + "options"
    posts = prefix + "posts"
    postmeta = prefix + "postmeta"
    comments = prefix + "comments"
    cap_key = prefix + "capabilities"
    found: list[Finding] = []
    try:
        try:
            _query(connection, "SET SESSION TRANSACTION READ ONLY")
        except Exception:
            pass
        version_rows = _query(connection, "SELECT VERSION() AS version")
        if version_rows:
            found.extend(_version_findings(client, str(version_rows[0].get("version") or "")))
        accounts = _query(
            connection,
            f"SELECT u.user_login, u.user_email, u.user_registered, m.meta_value AS caps "
            f"FROM `{users}` u LEFT JOIN `{usermeta}` m ON m.user_id = u.ID AND m.meta_key = %s",
            (cap_key,),
        )
        admins = []
        for row in accounts:
            login = str(row.get("user_login") or "")
            email = str(row.get("user_email") or "")
            caps = str(row.get("caps") or "")
            registered = str(row.get("user_registered") or "")
            if is_administrator(caps):
                admins.append(login)
            found.extend(classify_user(login, email, caps, registered))
        if admins:
            found.append(_finding(
                "info", "administrators", "Администраторы сайта",
                "users", ", ".join(admins)[:180],
                "Сверьте список с людьми, которым вы сами давали доступ. Лишних понизьте или удалите и смените пароли.",
            ))
        passwords = _query(
            connection,
            f"SELECT user_id, meta_value FROM `{usermeta}` "
            f"WHERE meta_key = '_application_passwords' AND meta_value NOT IN ('', 'a:0:{{}}') LIMIT 50",
        )
        if passwords:
            found.append(_finding(
                "info", "application-passwords",
                "Есть пароли приложений для REST API",
                "usermeta", f"записей: {len(passwords)}",
                "Пароль приложения входит в сайт без обычного входа. Удалите те, которые не узнаёте.",
            ))
        option_rows = _query(
            connection,
            f"SELECT option_name, "
            f"LOCATE('<?php', option_value) AS php_at, "
            f"LOCATE('eval(', option_value) AS eval_at, "
            f"LOCATE('dolly_', option_value) AS dolly_at, "
            f"LOCATE('<script', option_value) AS script_at, "
            f"LENGTH(option_value) AS n "
            f"FROM `{options}` "
            f"WHERE option_name <> 'rewrite_rules' AND ("
            f"option_name REGEXP '^[0-9a-fA-F]{{16,64}}$' "
            f"OR option_value LIKE %s OR option_value LIKE %s "
            f"OR option_value LIKE %s OR option_value LIKE %s) LIMIT 80",
            ("%<?php%", "%eval(%", "%dolly_%", "%<script%"),
        )
        for row in option_rows:
            found.extend(classify_option(
                str(row.get("option_name") or ""),
                int(row.get("php_at") or 0),
                int(row.get("eval_at") or 0),
                int(row.get("dolly_at") or 0),
                int(row.get("script_at") or 0),
                int(row.get("n") or 0),
            ))
        cron_rows = _query(
            connection,
            f"SELECT LOCATE('<?php', option_value) AS php_at, "
            f"LOCATE('eval(', option_value) AS eval_at, "
            f"LOCATE('dolly_', option_value) AS dolly_at, "
            f"LENGTH(option_value) AS n FROM `{options}` WHERE option_name = 'cron'",
        )
        if cron_rows:
            row = cron_rows[0]
            found.extend(classify_cron(
                int(row.get("php_at") or 0),
                int(row.get("eval_at") or 0),
                int(row.get("dolly_at") or 0),
                int(row.get("n") or 0),
            ))
        flags = _query(
            connection,
            f"SELECT option_name, option_value FROM `{options}` "
            f"WHERE option_name IN ('siteurl','home','users_can_register','default_role','active_plugins')",
        )
        values = {str(row["option_name"]): str(row.get("option_value") or "") for row in flags}
        if values.get("users_can_register") == "1":
            found.append(_finding(
                "medium", "open-registration", "Регистрация пользователей открыта",
                "option:users_can_register", "1",
                "Откройте регистрацию только если сайт действительно набирает пользователей.",
            ))
        if values.get("default_role") == "administrator":
            found.append(_finding(
                "critical", "default-role-admin", "Новые пользователи сразу становятся администраторами",
                "option:default_role", "administrator",
                "Верните роль subscriber. Иначе любой зарегистрированный получает полный доступ.",
            ))
        siteurl = values.get("siteurl", "")
        home = values.get("home", "")
        if siteurl and home and siteurl.rstrip("/") != home.rstrip("/"):
            found.append(_finding(
                "medium", "url-mismatch", "Адрес сайта и адрес WordPress различаются",
                "option:siteurl", f"siteurl={siteurl[:80]} home={home[:80]}",
                "Так бывает у установки в подкаталоге. Если вы этого не делали, адрес могли подменить.",
            ))
        for plugin_file in plugin_paths(values.get("active_plugins", "")):
            plugin_path = site.root / "wp-content" / "plugins" / plugin_file
            if not plugin_path.is_file():
                found.append(_finding(
                    "medium", "active-plugin-missing",
                    "В списке активных плагинов есть файл, которого нет на диске",
                    plugin_file, plugin_file,
                    "Уберите его из active_plugins. Иногда так оставляют след после удаления вредоносного плагина.",
                ))
        post_rows = _query(
            connection,
            f"SELECT ID, post_type, LEFT(post_title, 80) AS title, "
            f"LOCATE('<?php', post_content) AS php_at, "
            f"LOCATE('eval(', post_content) AS eval_at, "
            f"LOCATE('base64_decode', post_content) AS b64_at, "
            f"LOCATE('dolly_', post_content) AS dolly_at, "
            f"LOCATE('<iframe', post_content) AS iframe_at, "
            f"LOCATE('<script', post_content) AS script_at "
            f"FROM `{posts}` WHERE post_status NOT IN ('trash','auto-draft') AND ("
            f"post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s "
            f"OR post_content LIKE %s OR post_content LIKE %s OR post_content LIKE %s) LIMIT 80",
            ("%<?php%", "%eval(%", "%base64_decode%", "%dolly_%", "%<iframe%", "%<script%"),
        )
        for row in post_rows:
            found.extend(classify_post(
                int(row.get("ID") or 0),
                str(row.get("post_type") or ""),
                str(row.get("title") or ""),
                int(row.get("php_at") or 0),
                int(row.get("eval_at") or 0),
                int(row.get("b64_at") or 0),
                int(row.get("dolly_at") or 0),
                int(row.get("iframe_at") or 0),
                int(row.get("script_at") or 0),
            ))
        meta_rows = _query(
            connection,
            f"SELECT post_id, meta_key, "
            f"LOCATE('<?php', meta_value) AS php_at, LOCATE('eval(', meta_value) AS eval_at "
            f"FROM `{postmeta}` WHERE meta_value LIKE %s OR meta_value LIKE %s LIMIT 40",
            ("%<?php%", "%eval(%"),
        )
        for row in meta_rows:
            if int(row.get("php_at") or 0) or int(row.get("eval_at") or 0):
                found.append(_finding(
                    "high", "postmeta-code", "В поле записи есть PHP или eval",
                    f"postmeta #{row.get('post_id')} {row.get('meta_key')}",
                    f"php={row.get('php_at')} eval={row.get('eval_at')}",
                    "Проверьте это поле в базе. Чужой код в postmeta переживает чистку файлов.",
                ))
        comment_rows = _query(
            connection,
            f"SELECT comment_ID, LOCATE('<?php', comment_content) AS php_at, "
            f"LOCATE('<script', comment_content) AS script_at "
            f"FROM `{comments}` WHERE comment_content LIKE %s OR comment_content LIKE %s LIMIT 20",
            ("%<?php%", "%<script%"),
        )
        for row in comment_rows:
            severity = "critical" if int(row.get("php_at") or 0) else "medium"
            found.append(_finding(
                severity, "comment-code", "В комментарии есть код",
                f"comment #{row.get('comment_ID')}",
                f"php={row.get('php_at')} script={row.get('script_at')}",
                "Удалите комментарий, если скрипт поставили не вы.",
            ))
    except Exception as exc:
        found.append(_finding(
            "high", "database-query", "Ошибка при чтении базы",
            config.db_name or "", _hide(str(exc), config.db_password),
            "Проверка остановилась на этом запросе. Остальные разделы отчёта сохраняются.",
        ))
    finally:
        connection.close()
    return found
