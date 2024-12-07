{% if not auth-success %}
    {{auth-error}}
{% endif %}

<form action="/user/login/" method="post">
    <input id="csrf_token" type="hidden" name="csrf_token" value="{{csrf_token}}">
    <p>
        <label for="user-login">Логин:</label>
        <input id="user-login" type="text" name="login">
    </p>
    <p>
        <label for="user-login">Пароль:</label>
        <input id="user-password" type="password" name="password">
    </p>
    <p>
        <label for="user-remember">Запомнить:</label>
        <input  id=”user-remember” type="checkbox" name='user-remember' value='remember'>
    </p>
    <p>
        <input type="submit" value="Войти">
    </p>
</form>