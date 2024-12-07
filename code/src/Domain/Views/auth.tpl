{% if not user_authorised %}
    <p><a href="/user/auth/">Вход в систему</a></p>
{% else %}
    <p>Добро пожаловать на сайт {{ user_name }}!</p>
    <a href="/user/logout">Выход из системы</a>
{% endif %}